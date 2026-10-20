#!/bin/sh
# Focused adversarial fixtures for check-sums.sh. Run with sh from any cwd.
set -u

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
scratch=$(mktemp -d) || exit 2
trap 'rm -rf "$scratch"' EXIT INT TERM

fail() {
    echo "check-sums.test.sh: $1" >&2
    exit 1
}

fixture() {
    name=$1
    phase=$2
    root=$scratch/$name
    mkdir -p "$root/vectors/v1/baseline/rsa-oaep-envelope-open" || exit 2
    cp "$here/check-sums.sh" "$here/read-sets.sh" "$root/vectors/" || exit 2
    printf 'v1/baseline/rsa-oaep-envelope-open\n' > "$root/vectors/sets.txt"
    printf '{"set":"rsa-oaep-envelope-open","phase":"%s"}\n' "$phase" > "$root/vectors/v1/baseline/rsa-oaep-envelope-open/set.json"
    printf '{"vectorFormat":1}\n' > "$root/vectors/v1/baseline/rsa-oaep-envelope-open/vector.json"
    (cd "$root/vectors/v1/baseline/rsa-oaep-envelope-open" && sha256sum vector.json > SHA256SUMS) || exit 2
}

fixture valid devel
sh "$scratch/valid/vectors/check-sums.sh" > "$scratch/valid.out" 2>&1 || fail "valid manifest fixture failed"
grep -qx 'CHECKED SETS: 1' "$scratch/valid.out" || fail "valid fixture did not report one checked set"

# A listed baseline package cannot grow a JSON member outside its checksum file.
fixture baseline-member devel
printf '{"vectorFormat":3}\n' > "$scratch/baseline-member/vectors/v1/baseline/rsa-oaep-envelope-open/unlisted.json"
if sh "$scratch/baseline-member/vectors/check-sums.sh" > "$scratch/baseline-member.out" 2>&1; then
    fail "unlisted baseline member returned green"
fi
grep -q 'unlisted.json: not named in SHA256SUMS' "$scratch/baseline-member.out" \
    || fail "unlisted baseline member was not reported"

# A full checksum walk reads every set the manifest names. The second set here
# carries bytes that no longer match its sums file, so the walk has to check it,
# count it and end red.
fixture second-set devel
mkdir "$scratch/second-set/vectors/later" || exit 2
printf 'later\n' >> "$scratch/second-set/vectors/sets.txt"
printf '{"set":"later","phase":"devel"}\n' > "$scratch/second-set/vectors/later/set.json"
printf '{"vectorFormat":1}\n' > "$scratch/second-set/vectors/later/vector.json"
(cd "$scratch/second-set/vectors/later" && sha256sum vector.json > SHA256SUMS) || exit 2
printf 'x' >> "$scratch/second-set/vectors/later/vector.json"
set +e
sh "$scratch/second-set/vectors/check-sums.sh" > "$scratch/second-set.out" 2>&1
second_set_status=$?
set -e
[ "$second_set_status" -eq 1 ] || fail "changed second set returned $second_set_status, not the mismatch 1"
grep -q 'set later, phase devel: FAILED' "$scratch/second-set.out" \
    || fail "the changed second set was not checked"
grep -qx 'CHECKED SETS: 2' "$scratch/second-set.out" \
    || fail "the full manifest walk did not count every listed set"

# A listed nested package with an extra unhashed member must fail the full
# walk; its parent v1 set must not make the member invisible.
fixture nested-member devel
nested="$scratch/nested-member/vectors/v1/profiles/dca-profile-client-bound-ecdh-p256"
mkdir -p "$nested" || exit 2
printf 'v1/profiles/dca-profile-client-bound-ecdh-p256\n' >> "$scratch/nested-member/vectors/sets.txt"
printf '{"set":"v1/profiles/dca-profile-client-bound-ecdh-p256","phase":"devel"}\n' > "$nested/set.json"
printf '{"vectorFormat":"profile"}\n' > "$nested/vector.json"
(cd "$nested" && sha256sum vector.json > SHA256SUMS) || exit 2
printf '{"vectorFormat":"profile"}\n' > "$nested/unlisted.json"
set +e
sh "$scratch/nested-member/vectors/check-sums.sh" > "$scratch/nested-member.out" 2>&1
nested_status=$?
set -e
[ "$nested_status" -eq 1 ] || fail "unlisted nested member returned $nested_status, not mismatch 1"
grep -q 'unlisted.json: not named in SHA256SUMS' "$scratch/nested-member.out" \
    || fail "unlisted nested member was not reported"
grep -qx 'CHECKED SETS: 2' "$scratch/nested-member.out" \
    || fail "nested package was not checked with the base set"

fixture experiment-member devel
experiment="$scratch/experiment-member/vectors/v1/experiments/bind-on-renderId-and-slot"
mkdir -p "$experiment" || exit 2
printf 'v1/experiments/bind-on-renderId-and-slot\n' >> "$scratch/experiment-member/vectors/sets.txt"
printf '{"set":"bind-on-renderId-and-slot","phase":"devel"}\n' > "$experiment/set.json"
printf '{"vectorFormat":4}\n' > "$experiment/bind-blobs.json"
(cd "$experiment" && sha256sum bind-blobs.json > SHA256SUMS) || exit 2
printf '{"vectorFormat":4}\n' > "$experiment/unlisted.json"
set +e
sh "$scratch/experiment-member/vectors/check-sums.sh" > "$scratch/experiment-member.out" 2>&1
experiment_status=$?
set -e
[ "$experiment_status" -eq 1 ] || fail "unlisted experiment member returned $experiment_status, not mismatch 1"
grep -q 'unlisted.json: not named in SHA256SUMS' "$scratch/experiment-member.out" \
    || fail "unlisted experiment member was not reported"

set +e
sh "$scratch/valid/vectors/check-sums.sh" v1-typo > "$scratch/typo.out" 2>&1
typo_status=$?
set -e
[ "$typo_status" -eq 2 ] || fail "missing named set returned $typo_status, not setup refusal 2"
grep -qx 'check-sums.sh: no such set: v1-typo' "$scratch/typo.out" || fail "missing named set was not identified"
if grep -q '^CHECKED SETS:' "$scratch/typo.out"; then
    fail "missing named set made a checksum claim"
fi

fixture missing ''
if sh "$scratch/missing/vectors/check-sums.sh" > "$scratch/missing.out" 2>&1; then
    fail "missing phase returned green"
fi
grep -q 'phase missing: FAILED' "$scratch/missing.out" || fail "missing phase was not identified"

rm "$scratch/missing/vectors/v1/baseline/rsa-oaep-envelope-open/SHA256SUMS" || exit 2
if sh "$scratch/missing/vectors/check-sums.sh" --write > "$scratch/missing-write.out" 2>&1; then
    fail "missing phase wrote a new sums file"
fi
[ ! -e "$scratch/missing/vectors/v1/baseline/rsa-oaep-envelope-open/SHA256SUMS" ] || fail "missing phase wrote SHA256SUMS"

fixture unknown draft
set +e
sh "$scratch/unknown/vectors/check-sums.sh" > "$scratch/unknown.out" 2>&1
unknown_status=$?
set -e
[ "$unknown_status" -eq 2 ] || fail "unknown phase returned $unknown_status, not setup refusal 2"
grep -q 'phase draft: FAILED' "$scratch/unknown.out" || fail "unknown phase was not identified"
grep -q 'have no usable phase' "$scratch/unknown.out" || fail "unknown phase result claimed the phase was absent"

rm "$scratch/unknown/vectors/v1/baseline/rsa-oaep-envelope-open/SHA256SUMS" || exit 2
if sh "$scratch/unknown/vectors/check-sums.sh" --write > "$scratch/unknown-write.out" 2>&1; then
    fail "unknown phase wrote a new sums file"
fi
[ ! -e "$scratch/unknown/vectors/v1/baseline/rsa-oaep-envelope-open/SHA256SUMS" ] || fail "unknown phase wrote SHA256SUMS"

fixture nophase devel
printf '{"set":"rsa-oaep-envelope-open"}\n' > "$scratch/nophase/vectors/v1/baseline/rsa-oaep-envelope-open/set.json" || exit 2
set +e
sh "$scratch/nophase/vectors/check-sums.sh" > "$scratch/nophase.out" 2>&1
nophase_status=$?
set -e
[ "$nophase_status" -eq 2 ] || fail "set.json declaring no phase returned $nophase_status, not setup refusal 2"
grep -q 'phase missing: FAILED' "$scratch/nophase.out" || fail "set.json declaring no phase was not identified"
grep -qx '  set.json must declare phase devel or stable' "$scratch/nophase.out" \
    || fail "set.json declaring no phase did not name the declaration it wants"

fixture absent devel
rm "$scratch/absent/vectors/v1/baseline/rsa-oaep-envelope-open/set.json" "$scratch/absent/vectors/v1/baseline/rsa-oaep-envelope-open/SHA256SUMS" || exit 2
if sh "$scratch/absent/vectors/check-sums.sh" --write > "$scratch/absent.out" 2>&1; then
    fail "absent set.json wrote a new sums file"
fi
[ ! -e "$scratch/absent/vectors/v1/baseline/rsa-oaep-envelope-open/SHA256SUMS" ] || fail "absent set.json wrote SHA256SUMS"

printf 'check-sums adversarial fixtures: PASS\n'
