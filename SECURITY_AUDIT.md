# Lexbor Security Audit

- **Target:** lexbor (HTML/CSS/URL/Encoding browser-engine toolkit), version 3.1.0
- **Commit audited:** `145872a`
- **Date:** 2026-11-09
- **Method:** Full source review of every module, backed by an AddressSanitizer + UndefinedBehaviorSanitizer build (`gcc -fsanitize=address,undefined`), targeted proof-of-concept programs, and multi-million-iteration mutation fuzzing of the tokenizers, parsers, and codecs. The existing 149-test suite passes cleanly under ASan/UBSan.
- **Scope:** `source/lexbor/{core,html,dom,css,selectors,style,url,punycode,unicode,encoding,utils,tag,ns,engine}` plus the POSIX/Windows ports and the wasm glue.

## Threat model

The attacker controls the bytes fed to the parsers: HTML documents (including chunked delivery with arbitrary boundaries), CSS text (stylesheets, `<style>`, inline `style`, selector strings), URLs and domain names, and the byte streams handed to the encoding codecs. The embedding application (for example PHP's DOM/URL extensions, Nokolexbor, Selectolax) is trusted but may legitimately pass any length or call any public API. Findings are rated by what the attacker-controlled *input* can reach through a normal application.

## Summary of findings

| # | Severity | Module | Defect | Attacker reach |
|---|----------|--------|--------|----------------|
| 1 | **High** | HTML tokenizer | Heap buffer overflow (1-byte OOB write) decoding named character references | Default `lxb_html_document_parse`, any HTML |
| 2 | **High** | CSS selectors | Invalid free / heap corruption parsing malformed `:lexbor-contains()` | Public `lxb_css_selectors_parse`, any selector string |
| 3 | **High** | CSS / core | Out-of-bounds read + signed-overflow serializing `INT64_MIN` integer values | Parse + serialize of any integer CSS property |
| 4 | **Medium** | HTML tree / serialize | Stack-overflow DoS serializing deeply nested `<template>` | Default parse + serialize |
| 5 | **Medium** | CSS selectors | Type-confused pointer deref matching `:is(:lexbor-contains(` | `lxb_css_selectors_parse` + matching |
| 6 | **Medium** | CSS selectors | Stack-overflow DoS serializing deeply nested `:is()/:not()/:has()` | Re-serialization of attacker CSS |
| 7 | **Medium** | URL / unicode | 1-byte OOB read in `lxb_unicode_idna_validity_criteria` with CHECK_HYPHENS | Direct IDNA API (not the URL parser) |
| 8 | **Medium** | URL | `URLSearchParams.sort()` corrupts list, silently drops entries | Public URLSearchParams API |
| 9 | **Medium** | DOM | Use-after-free moving a node between documents (`adopt` is a stub) | Cross-document DOM API |
| 10 | **Medium** | Encoding | ISO-2022-JP encoder state desync on small-buffer retry | Encode into bounded buffer (engine transcode) |
| 11 | **Medium** | Encoding | ISO-2022-JP encoder escape-sequence injection | Encode attacker code points |
| 12 | **Medium** | Encoding | GB18030/GBK chunked decoder corruption via stale `prepend` | Streaming decode of attacker bytes |

Plus roughly twenty Low / Informational robustness issues (listed per module below). The core memory engine (`mraw`, `mem`, `dobject`, `str`, hash/BST/AVL) held up under a 2-million-operation stress harness and end-to-end parser fuzzing with no memory errors; its issues are all latent API-robustness ones.

Every High and Medium finding was reproduced on the sanitizer build except where noted as logic-only; the reproductions are confirmed by this audit, not only by the per-module review.

---

## High-severity findings

### 1. Heap buffer overflow in named character reference decoding

- **File:** `source/lexbor/html/tokenizer/state.c:2270` (guard at `:2258`).
- **Impact:** 1-byte heap out-of-bounds **write**, reachable from the default public API with purely attacker-controlled HTML and no special options.

In `lxb_html_tokenizer_state_char_ref_named`, after a named entity matches, the decoded value is copied over the consumed `&name;` text. The capacity/realloc check lives inside `if (tail_size != 0)`:

```c
if (tail_size != 0) {
    if ((size + tail_size) + start > tkz->end) {
        if (lxb_html_tokenizer_temp_realloc(tkz, size) != LXB_STATUS_OK) { ... }
        start = &tkz->start[tkz->entity_start];
    }
    memmove(start + tkz->entity_match->value_len, tkz->pos - tail_size, tail_size);
}
memcpy(start, tkz->entity_match->value, tkz->entity_match->value_len);   /* line 2270 */
```

When `tail_size == 0` (the entity sits at the current end of the temp buffer) the `memcpy` runs with **no bounds check**. The code assumes `value_len <= size` (the consumed byte count), but two entities break that invariant: `&nGt;` and `&nLt;` each decode to a 6-byte UTF-8 value from a 5-byte source. When the entity ends exactly on the 16384-byte temp-buffer boundary, the 6-byte copy writes one byte past the allocation.

**Reproduced under ASan** (input: 16379 `A` bytes followed by `&nGt;`, via `lxb_html_document_parse`):

```
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 6
  #2 lxb_html_tokenizer_state_char_ref_named .../tokenizer/state.c:2270
  #6 lxb_html_document_parse .../html/interfaces/document.c:186
0x... is located 0 bytes after 16384-byte region
```

Also fires through the 1-byte chunked API from the EOF flush. The overflow byte is a partly attacker-chosen value, making this a classic corruption primitive.

**Fix:** perform the capacity check unconditionally against `value_len + tail_size`, realloc if needed, then `memmove`/`memcpy`.

### 2. Invalid free / heap corruption parsing malformed `:lexbor-contains()`

- **Files:** root cause `source/lexbor/css/selectors/state.c:1889`; crash at `source/lexbor/css/selectors/selector.c:351`; failure path in `pseudo_state.c`.
- **Impact:** heap corruption (wrong-allocator / wrong-type free) reachable from the public `lxb_css_selectors_parse` with an attacker-controlled selector string.

When a `:lexbor-contains()` has an empty or invalid argument, its failure path returns without resetting `parser->selectors->list` to `NULL` (the success paths do). `lxb_css_selectors_state_restore_parent` then overwrites the pseudo node's payload with that stale list pointer:

```c
if (selectors->list != NULL) {
    last->last->u.pseudo.data = selectors->list;   /* state.c:1889 */
}
```

During error-recovery cleanup, the destructor treats that `lxb_css_selector_list_t` as a `lxb_css_selector_contains_t` and calls `lexbor_mraw_free` on it and its "string" — freeing a pointer that was never an mraw allocation of that type.

**Reproduced under ASan** (selector `:lexbor-contains():has(`):

```
ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 8
  #1 lexbor_mraw_free core/mraw.c:387
  #2 lxb_css_selector_destroy_pseudo_class_function css/selectors/selector.c:351
  #9 lxb_css_selectors_parse_process css/selectors/selectors.c:196
```

On a release build this corrupts the mraw free list. It affects applications that call the selector-parsing API directly (a `querySelector`-style interface); it is **not** reached through `<style>`/`lxb_css_stylesheet_parse`.

**Fix:** reset `parser->selectors->list = NULL` in the `:lexbor-contains()` failure paths; defensively, `restore_parent` should not store a list pointer into the payload of a function type that owns a non-list value.

### 3. OOB read + signed overflow serializing `INT64_MIN` integer values

- **Files:** `source/lexbor/core/conv.h:44` (`lexbor_conv_double_to_long`), `source/lexbor/core/conv.c:42`/`:84`, reached via `source/lexbor/css/value.c:135`.
- **Impact:** out-of-bounds read of adjacent `.rodata` emitted into serialized output (small information disclosure) plus signed-overflow UB; crash on hardened builds. Reachable by parsing then serializing an integer CSS property.

`lexbor_conv_double_to_long` only clamps when `number < (double)LONG_MIN`. The value `-9223372036854775808.0` equals `(double)LONG_MIN` exactly, so it is stored unclamped as `LONG_MIN`. At serialization, `lexbor_conv_int64_to_data` does `num = -num`; negating `INT64_MIN` is UB and leaves `num` negative, so the digit loop indexes the `"0123456789"` global with a negative index.

**Reproduced under ASan/UBSan** (`a{z-index:-9223372036854775808}`):

```
core/conv.c:42:17: runtime error: negation of -9223372036854775808 cannot be represented in type 'long int'
AddressSanitizer: global-buffer-overflow ... READ of size 1 ... conv.c:84 ... 8 bytes before '0123456789'
```

Confirmed for `z-index`, `order`, and `float-defer`. The writes stay within the 128-byte stack buffer; the defect is a read overflow plus UB.

**Fix:** clamp symmetrically in `lexbor_conv_double_to_long`, and compute magnitude as `uint64_t` in `lexbor_conv_int64_to_data` so `INT64_MIN` is handled without negation.

---

## Medium-severity findings

### 4. Stack-overflow DoS serializing nested `<template>`

`source/lexbor/html/serialize.c:302` (and the pretty path `:1071`, and `serialize_ext.c:1373`). The serializer is otherwise iterative, but for a `<template>` it recurses into `template->content`, so recursion depth equals template nesting depth. Parsing is iterative, so `<template>`×N parses fine; the crash hits on the ubiquitous parse-then-serialize path. About 7k–9k nested templates (~70–90 KB input) overflow a 1 MB thread stack; depth is unbounded. **Reproduced under ASan** (stack-overflow in `lxb_html_serialize_node_cb`). Fix: serialize template content iteratively or cap nesting depth; apply to all three serializers.

### 5. Type-confused deref matching `:is(:lexbor-contains(`

`source/lexbor/selectors/selectors.c:2170`. Same root cause as finding 2: inside a forgiving `:is()/:where()/:has()`, the surviving `:lexbor-contains` node's `data` points at the parent list object, and the matcher reads `contains->insensitive` / `contains->str` from it. **UBSan-confirmed** (`load of value 88, which is not a valid value for type '_Bool'`). A controlled OOB was not demonstrated (the aliased length field was huge), but it is genuine type-confused use with attacker-influenced fields. Fix: as finding 2, plus have the matcher treat a null/invalid payload as a non-match.

### 6. Stack-overflow DoS serializing nested `:is()/:not()/:has()`

`source/lexbor/css/selectors/selector.c` (`serialize_chain` → `serialize_pseudo_class_function` at `:832` → `serialize_list_chain` at `:544`). No depth limit; ~40k nested (~150 KB) overflows the default 8 MB stack during `lxb_css_selector_serialize_list` / `lxb_css_rule_serialize`. **Reproduced under ASan.** Parse, match, and destroy are all iterative and handled 500k depth cleanly; serialization is the only recursive path. Fix: cap nesting depth.

### 7. OOB read in `lxb_unicode_idna_validity_criteria` (CHECK_HYPHENS)

`source/lexbor/unicode/idna.c:549`. In the byte-API branch with CHECK_HYPHENS set, the code evaluates `p[-1]` where `p == data`, reading one byte before the buffer (should be `p[length-1]`, as the code-point branch at `:533` does). **Reproduced under ASan** (`READ ... 1 bytes before 3-byte region`). This is a public API; lexbor's own URL host path uses the code-point variant with other flags, so it is **not** reachable through URL parsing, but it is reachable by any caller passing attacker label bytes with CHECK_HYPHENS. Fix: use `p[length-1]`.

### 8. `URLSearchParams.sort()` corrupts the list

`source/lexbor/url/url.c:5719`. After the insertion sort rebuilds the forward list, `search_params->last` is set from the last node of the *original* list, not the sorted tail, so it can point at a middle node. A subsequent `append`/`set`/`delete` splices after that node and silently drops every entry that followed it, while `length` over-counts. **Reproduced**: after sort + append, two entries are lost and the length field desyncs. Fully public API. Fix: set `last` to the real sorted tail and repair `prev` links.

### 9. Use-after-free moving a node between documents

`source/lexbor/dom/interfaces/node.c:1809` (`lxb_dom_node_adopt` is a stub with a `TODO`). Appending/inserting a node owned by document A into document B never updates `owner_document`; destroying A frees its `mraw` arena, leaving a dangling child in B. **Reproduced under ASan** (`heap-use-after-free` walking B's children after destroying A). Requires cross-document DOM calls (API misuse), not reachable from parsing a single document. Fix: implement the adopt step (reuse the clone/import re-interning logic) or reject cross-document inserts with `WRONG_DOCUMENT_ERR`.

### 10. ISO-2022-JP encoder state desync on small-buffer retry

`source/lexbor/encoding/encode.c:454`. The pre-code-point `state` is captured once per call, not per code point, so when one code point completes a mode switch and the next hits SMALL_BUFFER, the encoder rolls back to the wrong mode. On retry it emits ASCII while the stream is still in JIS0208/Roman mode, and `finish` omits the closing `ESC ( B`. The in-tree transcode loop (`engine.c:204`, 4 KiB buffer) triggers this on buffer-aligned input. **Reproduced**: `U+3042 U+3044 'A' 'B'` through 6-byte buffers loses `AB` into a kanji. Fix: capture `state` inside the loop (as the `_single` variant does).

### 11. ISO-2022-JP encoder escape-sequence injection

`source/lexbor/encoding/encode.c:544` (and `:1533`). In JIS0208 mode the encoder writes `0x0E`/`0x0F`/`0x1B` verbatim instead of treating them as errors, letting an attacker who controls code points inject `ESC`-based sequences into the output byte stream; a downstream decoder then reframes following ASCII as double-byte characters (content hiding / filter evasion). **Reproduced.** Fix: reject those three code points in the JIS0208 case (emit `ESC ( B`, switch to ASCII, then error), in both encoder variants.

### 12. GB18030/GBK chunked decoder corruption via stale `prepend`

`source/lexbor/encoding/decode.c:1756`. On an in-line fourth-byte error the decoder sets `ctx->prepend = true` but never clears it on that path (only the resume paths clear it). A later valid four-byte sequence split on a chunk boundary is then resumed through the wrong branch, destroying the character and cascading desync through the rest of the stream. Affects any streaming GBK/GB18030 consumer (for example HTML chunked parsing with that encoding). **Reproduced**: chunked decode diverges from whole-buffer decode. Fix: clear `prepend` on the in-line recovery path.

---

## Lower-severity and informational issues (by module)

**Core** (all latent; parsers do not drive these paths): `lexbor_shs_entry_get_*_static` reads `key[-1]` on a zero-length key (ASan-confirmed; reachable via `tag.c` public lookups with an empty name); `lexbor_dtoa`/`lexbor_conv_float_to_data` can return a length greater than the supplied buffer, which becomes an OOB write only for a caller passing a tight buffer; `lexbor_conv_int64_to_data` 1-byte OOB write with `len==0` and `INT64_MIN` negation UB (the reachable instance is finding 3); exponent-accumulation overflow in `lexbor_conv_data_to_double`; `lexbor_dobject_by_absolute_position` chunk-packing assumption (no callers); near-`SIZE_MAX` allocation-size wraps in `mraw`.

**HTML tree:** `lxb_html_attribute_steps_replace` reads the `.remove` callback instead of `.replace` (`attribute_steps.c:152`); `lxb_html_interface_destroy` indexes the destructor table with an unchecked namespace (`interface.c:150`), latent OOB function-pointer call for a node with `ns >= 8` created via a namespace-aware API; a theoretical NULL deref in foster parenting with an empty stack (could not be reached).

**HTML tokenizer:** unbounded integer accumulation in attribute integer parsing (`common.c:70`, wrong value only); `null_count` field overloaded for PI target length (safe as PI tokens never reach the text builders — confirmed).

**DOM:** `lxb_dom_attr_set_value` leaks the old value buffer into the document arena when a `change` mutation callback is registered (unbounded growth on a long-lived document; `attr.c:236`); prefixed qualified-name lookups pass the wrong length and always return empty (`node.c:962`/`:1010`); `lxb_dom_element_prefix` leaves `*len` unset on success (`element.c:793`).

**CSS syntax:** signed-overflow UB combining the number exponent (`state.c:951` → `strtod.c:328`), memory-safe because `strtod` clamps to INF/0; embedded NUL bytes survive in url()/bad-url/string token `data` (length-based internally, a hazard only for downstream C-string consumers).

**CSS object model:** three unchecked `by_id` helpers (`property`, `at_rule`, `unit`) — no attacker path to an out-of-range id was found, but bounds checks would be prudent defense-in-depth.

**URL / unicode:** chunked `lxb_unicode_normalize` stalls and silently drops all later input after a zero-length UTF-8 lead byte at a chunk boundary (`unicode.c:333`); `lxb_url_str_copy` leaves `length` stale on its fast path, producing corrupted output when re-parsing into a populated URL object (`url.c:766`); a CheckHyphens code-point index is off-by-one versus spec (in-bounds); NFC of a leading-combining-mark run is not reordered.

**Encoding / utils / wasm:** single-byte encoders never advance `*cps` on success (`encode.c:60`), causing infinite re-encoding for pointer-driven callers; Big5 decoder livelocks with a one-slot output buffer; ISO-2022-JP decoder emits a spurious `U+0001` after a multi-code-point small-buffer replacement; `decode_finish_single` never reports a truncated trailing sequence; WARC quoted header values bypass the 128 KiB limit (`warc.c:468`, linear memory DoS); UTF-8 and GB18030 encoders accept surrogates and values above `U+10FFFF`; a wasm glue UAF on allocation failure and a 1 MiB serialization truncation that could be a sanitization-bypass vector if used that way.

---

## What was checked and found robust

- **Core memory engine:** 2,000,000-operation randomized `mraw` alloc/free/realloc stress with content verification, plus end-to-end hostile-input fuzzing of HTML, CSS, and URL — no heap overflow or use-after-free. The intricate tail-reclaim and shrink-to-cache paths hold.
- **HTML tree construction:** the adoption agency algorithm, the p-in-button-scope cache, open-elements / active-formatting bounds, and the new 3.0.0 `<select>`/`<option>`/`<selectedcontent>` steps are sound; nodes are pool-allocated and not individually freed during parsing, which structurally avoids mid-parse use-after-free. ~400k fuzz iterations clean.
- **CSS selectors matching:** the entry/nested object reuse and backtracking (including the recent nested-pseudo retry fix) survived 60k fuzz iterations with no UAF; An+B arithmetic and attribute matching with empty values are memory-safe.
- **URL parser:** IPv4/IPv6 parse and serialize, port parsing, percent-decoding, path dot-segment popping, Windows-drive lookaheads, and `lxb_url_clone` are correctly bounded; 6M fuzz iterations clean. Punycode and IDNA buffer-growth overflow guards are correct.
- **Encoding codecs:** every multi-byte table index formula was checked against its table size (Big5, EUC-KR, EUC-JP, Shift_JIS, GB18030 two-byte and four-byte binary search); UTF-8 overlong/surrogate rejection and cross-chunk state, UTF-16 handling, and the replacement-injection bounds checks are correct. No memory-safety error surfaced in ~9M codec iterations or 1.79M WARC/HTTP iterations.
- **Test suite:** all 149 existing tests pass under ASan + UBSan.

## Recommended remediation order

1. Findings 1 and 2 first — both are memory-corruption writes/frees reachable from a single public call on attacker input.
2. Finding 3 — reachable on the common parse-then-serialize path.
3. Findings 4 and 6 (serialization stack overflows) — add depth caps; cheap and broadly protective.
4. The remaining Medium findings, then the Low/Informational robustness fixes (several share root causes with the High findings, for example the `conv` clamp and the `:lexbor-contains` reset).

PoC programs and fuzzers for every reproduced finding are available under the audit's scratch directory and were run against the sanitizer build described above.
