# Part 1 semantic edges

Singleton controls for ordinary-union constants, projected raw stores, immutable origins,
and by-value unsized slot arguments. Expected outputs record semantic requirements before CI.
They do not establish target reachability or a complete failure set.

The immutable subrange/relocation/static legal fixtures require SUCCESS. If a path is not
initialized by an admitted origin or an independent existing static path, its failure is a
legal falseFAIL and a release limitation. Never change those expectations to uninitialized UB.
A negative qualifies only with its matched legal companion and exactly the intended hole
property; failures caused by unqualified initialized bytes do not qualify the hole.

The two by-value DST fixtures intentionally expect the exact unsupported-size reason for
both initialized and hole inputs. The Box is only the existing source form for moving a slice
by value; passing the Box or a reference would exercise a different edge. Compilation failure
or an earlier unrelated Unsupported does not qualify this test. By-reference legal/hole
fixtures and existing sized transfers remain supported companions.

Run with uninit checks enabled. Bind each actual MIR call/store, byte offset/mask, property
identity and the full failure set to the exact tested source. Existing strong JSON oracles,
mode boundaries, pairing/cycles, typed-data/padding and immutable masks remain required.
