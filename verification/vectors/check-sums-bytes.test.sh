#!/bin/sh
# Focused byte-integrity fixtures for check-sums.sh. Run with sh from any cwd.
#
# check-sums.test.sh covers the refusals that happen before any hashing: a set
# named on the command line that is not there, a phase that cannot be read, a
# --write that would record bytes nobody declared. This file covers the hash check
# itself: whether the bytes on disk still match the bytes that were recorded.
# Three ways they can fail to match: changed, gone, and never hashed at all.
set -u

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
scratch=$(mktemp -d) || exit 2
trap 'rm -rf "$scratch"' EXIT INT TERM

fail() {
    echo "check-sums-bytes.test.sh: $1" >&2
    exit 1
}

# One set holding one recorded vector, the shape a green run has.
# Every case below is that tree plus one edit, so each case tests its edit
# and not the fixture around it.
fixture() {
    name=$1
    root=$scratch/$name
    mkdir -p "$root/vectors/v1/baseline/rsa-oaep-envelope-open" || exit 2
    cp "$here/check-sums.sh" "$here/read-sets.sh" "$root/vectors/" || exit 2
    printf 'v1/baseline/rsa-oaep-envelope-open\n' > "$root/vectors/sets.txt"
    printf '{"set":"rsa-oaep-envelope-open","phase":"devel"}\n' > "$root/vectors/v1/baseline/rsa-oaep-envelope-open/set.json"
    printf '{"vectorFormat":1}\n' > "$root/vectors/v1/baseline/rsa-oaep-envelope-open/vector.json"
    (cd "$root/vectors/v1/baseline/rsa-oaep-envelope-open" && sha256sum vector.json > SHA256SUMS) || exit 2
}

run_check() {
    name=$1
    sh "$scratch/$name/vectors/check-sums.sh" > "$scratch/$name.out" 2>&1
    check_status=$?
}

# The fixture without any edit, so a red result below comes from the edit and not the
# tree. It also pins the line a green run prints, which the three
# cases after it must not be able to produce.
fixture recorded
run_check recorded
[ "$check_status" -eq 0 ] || fail "the recorded fixture returned $check_status"
grep -q 'every byte matches SHA256SUMS' "$scratch/recorded.out" \
    || fail "the recorded fixture did not report matching bytes"

# One byte appended after the recording. A hand edit, a bad merge
# and a partial checkout all leave the same result: a file whose contents
# no longer hash to what SHA256SUMS records.
fixture changed
printf 'x' >> "$scratch/changed/vectors/v1/baseline/rsa-oaep-envelope-open/vector.json" || exit 2
run_check changed
[ "$check_status" -eq 1 ] || fail "changed bytes returned $check_status, not the mismatch 1"
grep -q 'set rsa-oaep-envelope-open, phase devel: FAILED' "$scratch/changed.out" || fail "changed bytes did not fail the set"
if grep -q 'every byte matches' "$scratch/changed.out"; then
    fail "changed bytes still claimed matching bytes"
fi

# A vector the sums file names and disk no longer holds. A walk that hashed only
# what it found would report every file it saw matching and say nothing about
# the one that went missing, and the set would replay fewer vectors than it
# claims.
fixture gone
printf '{"vectorFormat":2}\n' > "$scratch/gone/vectors/v1/baseline/rsa-oaep-envelope-open/other.json" || exit 2
(cd "$scratch/gone/vectors/v1/baseline/rsa-oaep-envelope-open" && sha256sum vector.json other.json > SHA256SUMS) || exit 2
rm "$scratch/gone/vectors/v1/baseline/rsa-oaep-envelope-open/other.json" || exit 2
run_check gone
[ "$check_status" -eq 1 ] || fail "a missing vector returned $check_status, not the mismatch 1"
grep -q 'set rsa-oaep-envelope-open, phase devel: FAILED' "$scratch/gone.out" || fail "a missing vector did not fail the set"
grep -q 'other.json' "$scratch/gone.out" || fail "a missing vector was not named"

# A vector on disk that the sums file does not name. `sha256sum -c` walks the
# sums file and never checks disk for files it leaves out, so this is the one of the three
# that a plain hash check cannot see at all, and a vector nobody hashed is never
# replayed.
fixture unhashed
printf '{"vectorFormat":3}\n' > "$scratch/unhashed/vectors/v1/baseline/rsa-oaep-envelope-open/extra.json" || exit 2
run_check unhashed
[ "$check_status" -eq 1 ] || fail "an unhashed vector returned $check_status, not the mismatch 1"
grep -q 'extra.json: not named in SHA256SUMS' "$scratch/unhashed.out" \
    || fail "an unhashed vector was not reported"

printf 'check-sums byte-integrity fixtures: PASS\n'
