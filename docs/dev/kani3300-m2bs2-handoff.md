# KANI3300 M2-B/S2 — PREPARED/BLOCKER

Continuation of documentation-only 35fab624af; production remains exact5f7
(5f7f2b7364135a0a8b7cfd86c43b4491a8911bac). No Rust/model/test change.

Coordinator supplied C03 artifacts from CI4804129592, runs43248579074/43249480111.
The failed property SpecArrayEq<u8,3>::spec_eq.safety_check.1 is the LEFT raw_eq
CheckAs: transformed MIR _4 = is_ptr_initialized(_6,[true;3]), _6 = &raw const *_1.
The right check .2 succeeds. Body, ensures and root share this property.
Body left is generated body closure value (_16); ensures left is captured out
referent, not closure storage; root left is harness out. Their RHS resolves to
m2a.a7ad3e73aae47d8a::m2a::AllocId(1, ThreadLocalIndex) at byte offset0.
GOTO reset instruction6940 guards that object's range0..3 and instruction6941
seeds [true,true,true]. Missing initial RHS seed is therefore not established.
Compiler-local IDs, MIR alloc labels and runtime object numbers are distinct.

The file trace.txt is Kani regular rendered results, not a counterexample step
trace. It has 352 statuses (340 SUCCESS, 1 FAILURE, 11 UNREACHABLE), no State or
assignment history. Source renderer retains only the failure's final location.
The failing invocation, actual witness object/offset, last setter/retarget and
runtime seed branch remain UNKNOWN. Inner Assert body has no post-assume_init
setter for _16 and no setter after *out=_16; outer Original has such setters.
This is a next diagnostic candidate, not established causality or authority to
repair D0 or reseed mutable storage.

Next coordinator-only request: same C03 and exact source/flags/root, change
--output-format=regular to old; pass --cbmc-args --json-ui --trace with
-Z unstable-options, without concrete playback/compact trace. Old output
bypasses the Kani renderer and preserves CBMC JSON including trace steps.
Return only the failed property's ordered call/pointer/witness history plus
all property statuses/exits and identities, under existing timeout/RSS limits.
Research kani3300/m2bs2 records exact bindings, limitations and full request.
Cloud $0; local compiler/verifier0; no dispatch or Kani push. M2 semantic and
separate resource gates remain unresolved; M3 HELD. READY is a docs handoff.
