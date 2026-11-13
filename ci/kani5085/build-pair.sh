#!/usr/bin/env bash
# CI ONLY: one source directory, identical compiler/configuration, incremental fix.
set -euo pipefail
cd "$GITHUB_WORKSPACE"
mkdir -p pair evidence/build
exec > >(tee evidence/build/build-pair.log) 2>&1
sudo apt-get update
sudo apt-get install --no-install-recommends -y ninja-build gcc-13 g++-13 flex bison patch
uname -a
/usr/bin/gcc-13 --version
/usr/bin/g++-13 --version
cmake --version
ninja --version
cd cbmc
base=107a1e504cd69a2f3483717c8bcfcfa59814c557
fix=9f2d01ec2bf115879c86e22203d403ba156d22e5
test "$(git rev-parse HEAD)" = "$fix"
test "$(git rev-parse HEAD^)" = "$base"
python3 ../overlay/ci/kani5085/replay.py check-delta "$PWD"
git diff "$base" "$fix" -- src/util/simplify_utils.cpp > ../evidence/build/production.diff
git checkout --detach "$base"
test -z "$(git status --porcelain --untracked-files=no)"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DWITH_JBMC=OFF -DWITH_MEMORY_ANALYZER=OFF '-Dsat_impl=minisat2;cadical' \
  -DCMAKE_C_COMPILER=/usr/bin/gcc-13 -DCMAKE_CXX_COMPILER=/usr/bin/g++-13
# Same target/config as the focused upstream Release recipe, no unit/Java/all targets.
cmake --build build --target cbmc --parallel 2
cp build/bin/cbmc ../pair/base
python3 ../overlay/ci/kani5085/replay.py receipt base "$PWD" "$GITHUB_WORKSPACE/pair/base" "$GITHUB_WORKSPACE/evidence"
git checkout --detach "$fix"
test -z "$(git status --porcelain --untracked-files=no)"
# Reuse identical dependencies/objects; rebuild the changed TU and relink.
cmake --build build --target cbmc --parallel 2
cp build/bin/cbmc ../pair/fix
python3 ../overlay/ci/kani5085/replay.py receipt fix "$PWD" "$GITHUB_WORKSPACE/pair/fix" "$GITHUB_WORKSPACE/evidence"
