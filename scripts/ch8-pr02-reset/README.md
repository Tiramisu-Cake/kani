# CH8 PR-02 entry-reset CI draft

CI-only package built on PR-02 (`932fb8395a58f8c86c0d702ba2cae835823b2962`).
The coordinator must add this package as a same-tree child commit with `[skip ci]`
in its parent commit message and push the child to
`uninit-ci/ch8-pr02-reset-<unique-suffix>`. The workflow itself is deliberately
restricted to those trigger branches and the `Tiramisu-Cake/kani` repository.

`scripts/ch8-pr02-reset/reset.patch` is the source delta applied to each pinned
source checkout. Arm A applies it to PR-02 and also runs the matched old-control
cases against the unpatched PR-02 checkout. Arm B applies it to SEL1 and runs
the exact #4854 autoharness case plus its explicit proof companion. Runner
receipts distinguish setup failures from test failures; outputs are bounded to
the CI run and are not proof-credit records.

Before dispatch, run `python3 scripts/ch8-pr02-reset/check_package.py` and
record the final package commit, tree, source patch SHA256, fixture SHA256s,
and exact pins in `CI-REQUEST.json`. No local compiler or verifier invocation
is part of preparation. The CI-only commit must omit the stock push workflows
from `.github/workflows` (keep only `ch8-pr02-reset.yml`); source checkouts are
separate pinned worktrees, so those workflow deletions do not affect builds.

The current compiletest output oracle does not expose goto C or model JSON for
the wrappers. Reset count/order, nondeterministic witness offset, and OFF-mode
absence of runtime/model artifacts remain source-level/runtime review items;
do not infer them from regular expected output.
