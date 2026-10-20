#!/bin/sh
# Focused adversarial fixtures for read_set_manifest in read-sets.sh. Run with
# sh from any cwd.
#
# `check-sums.sh` trusts the reader to say which sets a walk covers, so
# the cases below are the ways a manifest and the directories beside it can
# disagree. Each one has to return 2 and say the run stopped, because a reader
# that answered 0 here hands a wrapper a short walk and the wrapper reports a
# green gate over it.
set -u

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
scratch=$(mktemp -d) || exit 2
trap 'rm -rf "$scratch"' EXIT INT TERM

fail() {
    echo "read-sets.test.sh: $1" >&2
    exit 1
}

# Every case gets its own vectors directory, because the reader answers about
# one manifest and the directories that sit beside it. A case borrowing another
# case's tree would be answering about both. The set directories are bare
# mkdirs: the reader checks only whether a name is a directory and never opens
# one.
case_dir() {
    root=$scratch/$1
    shift
    mkdir "$root" || exit 2
    cp "$here/read-sets.sh" "$root/read-sets.sh" || exit 2
    for set_name in "$@"; do
        mkdir "$root/$set_name" || exit 2
    done
}

# The reader is sourced, so every call runs in its own subshell: a case that
# left DCA_VECTOR_SETS behind would be answering for the next one.
run_case() {
    name=$1
    (
        # shellcheck source=read-sets.sh
        . "$scratch/$name/read-sets.sh"
        read_set_manifest "$scratch/$name/sets.txt" "$scratch/$name"
        status=$?
        # Unquoted on purpose. The reader accumulates names with a leading
        # space, and the word splitting here trims it before the
        # comparisons below read the list.
        # shellcheck disable=SC2086
        echo $DCA_VECTOR_SETS > "$scratch/$name.sets"
        exit "$status"
    ) > "$scratch/$name.out" 2> "$scratch/$name.err"
    case_status=$?
}

# A refusal is all three of these together: the status 2 a caller acts on, the
# complaint that names what was found, and the line saying the run stopped. A
# reader that returned 2 and said nothing is as unusable as one that returned 0,
# and stdout stays empty because that is where a caller reads results.
expect_refusal() {
    name=$1
    complaint=$2
    run_case "$name"
    [ "$case_status" -eq 2 ] || fail "$name returned $case_status, not the refusal 2"
    grep -qF "$complaint" "$scratch/$name.err" || fail "$name did not report: $complaint"
    grep -qF 'Nothing ran.' "$scratch/$name.err" || fail "$name did not say the run stopped"
    [ ! -s "$scratch/$name.out" ] || fail "$name wrote a result to stdout"
}

# Nothing on disk says which sets this run covers, so there is no walk to shorten
# and no set list to hand back.
case_dir manifest-missing
expect_refusal manifest-missing "$scratch/manifest-missing/sets.txt: not there."
[ -z "$(cat "$scratch/manifest-missing.sets")" ] || fail "manifest-missing handed back a set list"

# The manifest names a set that is not there. A checksum walk over this list
# would hash one set fewer than it set out to and still exit 0.
case_dir named-set-missing
printf 'alpha\n' > "$scratch/named-set-missing/sets.txt"
expect_refusal named-set-missing "names alpha, and $scratch/named-set-missing/alpha is not a directory."

# A set directory nobody named. The manifest exists to
# prevent this: vectors sitting in the tree that no walk hashes and no run mentions.
case_dir unnamed-directory alpha beta
printf 'alpha\n' > "$scratch/unnamed-directory/sets.txt"
expect_refusal unnamed-directory "$scratch/unnamed-directory/beta is a set directory and no $scratch/unnamed-directory/sets.txt line names it."

# A baseline algorithm package must be discovered at the exact supported depth.
case_dir baseline-package v1
mkdir -p "$scratch/baseline-package/v1/baseline/rsa-oaep-envelope-open" \
    "$scratch/baseline-package/v1/baseline/unlisted" || exit 2
printf 'v1/baseline/rsa-oaep-envelope-open\n' > "$scratch/baseline-package/sets.txt"
expect_refusal baseline-package "$scratch/baseline-package/v1/baseline/unlisted is a baseline package and no $scratch/baseline-package/sets.txt line names it."

case_dir baseline-agreed v1
mkdir -p "$scratch/baseline-agreed/v1/baseline/rsa-oaep-envelope-open" || exit 2
printf 'v1/baseline/rsa-oaep-envelope-open\n' > "$scratch/baseline-agreed/sets.txt"
run_case baseline-agreed
[ "$case_status" -eq 0 ] || fail "a listed baseline package returned $case_status"
[ "$(cat "$scratch/baseline-agreed.sets")" = "v1/baseline/rsa-oaep-envelope-open" ] \
    || fail "baseline package was omitted from the set list"

# Root v1/ is a container: neither a payload nor an old set manifest belongs there.
case_dir stranded-vector v1
mkdir -p "$scratch/stranded-vector/v1/baseline/rsa-oaep-envelope-open" || exit 2
printf 'v1/baseline/rsa-oaep-envelope-open\n' > "$scratch/stranded-vector/sets.txt"
printf '{}' > "$scratch/stranded-vector/v1/open-rsa-oaep.json"
expect_refusal stranded-vector "$scratch/stranded-vector/v1/open-rsa-oaep.json is stranded in the v1 container"

case_dir stranded-manifest v1
mkdir -p "$scratch/stranded-manifest/v1/baseline/rsa-oaep-envelope-open" || exit 2
printf 'v1/baseline/rsa-oaep-envelope-open\n' > "$scratch/stranded-manifest/sets.txt"
printf '{}' > "$scratch/stranded-manifest/v1/set.json"
expect_refusal stranded-manifest "$scratch/stranded-manifest/v1/set.json is stranded in the v1 container"

# Regression case: one listed package, and payloads dropped where no
# group scan looks. `check-sums.sh` hashed the listed package, printed
# "CHECKED SETS: 1" and exited 0 over the three files below. The reader has to
# name each of them, whatever depth it sits at.
case_dir off-layout v1
mkdir -p "$scratch/off-layout/v1/baseline/rsa-oaep-envelope-open/nested" \
    "$scratch/off-layout/v1/extras/hidden" || exit 2
printf 'v1/baseline/rsa-oaep-envelope-open\n' > "$scratch/off-layout/sets.txt"
printf '{}' > "$scratch/off-layout/v1/baseline/rsa-oaep-envelope-open/open-rsa-oaep.json"
printf '{}' > "$scratch/off-layout/v1/baseline/rsa-oaep-envelope-open/nested/vector.json"
printf '{}' > "$scratch/off-layout/v1/baseline/stray.json"
printf '{}' > "$scratch/off-layout/v1/extras/hidden/vector.json"
expect_refusal off-layout "$scratch/off-layout/v1/baseline/rsa-oaep-envelope-open/nested/vector.json sits outside the vector layout"
for stray in v1/baseline/stray.json v1/extras/hidden/vector.json; do
    grep -qF "$scratch/off-layout/$stray sits outside the vector layout" "$scratch/off-layout.err" \
        || fail "off-layout did not name $stray"
done
grep -qF "open-rsa-oaep.json" "$scratch/off-layout.err" \
    && fail "off-layout refused a member at the package depth"

# A root set is flat for the same reason: the checksum walk reads only its
# top-level files.
case_dir root-set-nested alpha
mkdir -p "$scratch/root-set-nested/alpha/deeper" || exit 2
printf 'alpha\n' > "$scratch/root-set-nested/sets.txt"
printf '{}' > "$scratch/root-set-nested/alpha/deeper/vector.json"
expect_refusal root-set-nested "$scratch/root-set-nested/alpha/deeper/vector.json sits outside the vector layout"

case_dir old-root-set v1
printf 'v1\n' > "$scratch/old-root-set/sets.txt"
expect_refusal old-root-set "$scratch/old-root-set/sets.txt has an invalid set path: v1 (container)"

# A nested profile package must be discovered at the exact supported depth.
case_dir nested-package v1
mkdir -p "$scratch/nested-package/v1/profiles/dca-profile-client-bound-ecdh-p256" \
    "$scratch/nested-package/v1/profiles/dca-profile-client-bound-rsa-oaep" || exit 2
printf 'v1/profiles/dca-profile-client-bound-ecdh-p256\n' > "$scratch/nested-package/sets.txt"
expect_refusal nested-package "$scratch/nested-package/v1/profiles/dca-profile-client-bound-rsa-oaep is a profile package and no $scratch/nested-package/sets.txt line names it."

case_dir nested-agreed v1
mkdir -p "$scratch/nested-agreed/v1/profiles/dca-profile-client-bound-ecdh-p256" || exit 2
printf 'v1/profiles/dca-profile-client-bound-ecdh-p256\n' > "$scratch/nested-agreed/sets.txt"
run_case nested-agreed
[ "$case_status" -eq 0 ] || fail "a listed nested profile package returned $case_status"
[ "$(cat "$scratch/nested-agreed.sets")" = "v1/profiles/dca-profile-client-bound-ecdh-p256" ] \
    || fail "nested package was omitted from the set list"

case_dir experiment-package v1
mkdir -p "$scratch/experiment-package/v1/experiments/bind-on-renderId-and-slot" || exit 2
printf 'v1/experiments/bind-on-renderId-and-slot\n' > "$scratch/experiment-package/sets.txt"
mkdir -p "$scratch/experiment-package/v1/experiments/unlisted" || exit 2
expect_refusal experiment-package "$scratch/experiment-package/v1/experiments/unlisted is an experiment package and no $scratch/experiment-package/sets.txt line names it."

case_dir experiment-agreed v1
mkdir -p "$scratch/experiment-agreed/v1/experiments/bind-on-renderId-and-slot" || exit 2
printf 'v1/experiments/bind-on-renderId-and-slot\n' > "$scratch/experiment-agreed/sets.txt"
run_case experiment-agreed
[ "$case_status" -eq 0 ] || fail "a listed experiment package returned $case_status"
[ "$(cat "$scratch/experiment-agreed.sets")" = "v1/experiments/bind-on-renderId-and-slot" ] \
    || fail "experiment package was omitted from the set list"

# A set named twice would be hashed twice and reported twice.
case_dir named-twice alpha
printf 'alpha\nalpha\n' > "$scratch/named-twice/sets.txt"
expect_refusal named-twice "$scratch/named-twice/sets.txt names alpha more than once, and a set is walked one way."

# A data line carries one set directory. A second word would be read as a set
# name by a parser that took the last word, or dropped by one that took the
# first.
case_dir extra-field
printf 'alpha extra\n' > "$scratch/extra-field/sets.txt"
expect_refusal extra-field '2 field(s) where 1 is expected: "alpha extra"'

# A manifest of comments and blank lines parses cleanly and describes no walk at
# all, which is the one shape that would otherwise pass every check above.
case_dir names-no-sets
printf '# which sets this run walks\n\n#   nothing yet\n\n' > "$scratch/names-no-sets/sets.txt"
expect_refusal names-no-sets "$scratch/names-no-sets/sets.txt names no sets, so this run would walk nothing."
[ -z "$(cat "$scratch/names-no-sets.sets")" ] || fail "names-no-sets handed back a set list"

# The reader belongs to the checksum walk, which supplies exactly the manifest
# and its vectors directory. A third argument must not silently narrow that
# walk by reviving the obsolete profile-selection contract.
case_dir extra-argument alpha
printf 'alpha\n' > "$scratch/extra-argument/sets.txt"
(
    . "$scratch/extra-argument/read-sets.sh"
    read_set_manifest "$scratch/extra-argument/sets.txt" "$scratch/extra-argument" ignored
) > "$scratch/extra-argument.out" 2> "$scratch/extra-argument.err"
case_status=$?
[ "$case_status" -eq 2 ] || fail "extra-argument returned $case_status, not the refusal 2"
grep -qF 'read_set_manifest: expected 2 arguments (manifest and vectors directory), got 3.' "$scratch/extra-argument.err" \
    || fail "extra-argument did not reject the obsolete third argument"
grep -qF 'Nothing ran.' "$scratch/extra-argument.err" || fail "extra-argument did not say the run stopped"
[ ! -s "$scratch/extra-argument.out" ] || fail "extra-argument wrote a result to stdout"

# The reader reports every disagreement together rather than only the first one, so
# an operator fixing a manifest sees the whole list in one run. A missing named
# set and an unnamed directory at once prove it.
case_dir two-disagreements beta
printf 'alpha\n' > "$scratch/two-disagreements/sets.txt"
expect_refusal two-disagreements "names alpha, and $scratch/two-disagreements/alpha is not a directory."
grep -qF "$scratch/two-disagreements/beta is a set directory" "$scratch/two-disagreements.err" \
    || fail "two-disagreements reported one disagreement and stopped"

# The agreed tree, so the refusals above are the reader disagreeing and not the
# reader refusing everything.
case_dir agreed alpha beta
printf 'alpha\nbeta\n' > "$scratch/agreed/sets.txt"
run_case agreed
[ "$case_status" -eq 0 ] || fail "the agreed manifest returned $case_status"
[ "$(cat "$scratch/agreed.sets")" = "alpha beta" ] \
    || fail "agreed sets are $(cat "$scratch/agreed.sets"), not alpha beta"
[ ! -s "$scratch/agreed.err" ] || fail "the agreed manifest drew a complaint"

# The agreed layout with members in it, so the layout check refuses only what
# sits off the layout: package members, root-set members and the tooling beside
# sets.txt all pass.
case_dir layout-agreed v1 alpha
mkdir -p "$scratch/layout-agreed/v1/baseline/rsa-oaep-envelope-open" \
    "$scratch/layout-agreed/v1/profiles/dca-profile-chain-keys" \
    "$scratch/layout-agreed/v1/experiments/bind-on-renderId-and-slot" || exit 2
printf 'alpha\nv1/baseline/rsa-oaep-envelope-open\nv1/profiles/dca-profile-chain-keys\nv1/experiments/bind-on-renderId-and-slot\n' \
    > "$scratch/layout-agreed/sets.txt"
for member in alpha/a.json v1/baseline/rsa-oaep-envelope-open/set.json \
    v1/baseline/rsa-oaep-envelope-open/SHA256SUMS \
    v1/profiles/dca-profile-chain-keys/chain-key-primitives.json \
    v1/experiments/bind-on-renderId-and-slot/bind-blobs.json README.md check-sums.sh; do
    printf '{}' > "$scratch/layout-agreed/$member" || exit 2
done
run_case layout-agreed
[ "$case_status" -eq 0 ] || fail "the agreed layout returned $case_status: $(cat "$scratch/layout-agreed.err")"
[ ! -s "$scratch/layout-agreed.err" ] || fail "the agreed layout drew a complaint"

# Splitting a manifest line needs globbing off and the directory scan needs it
# on, and the reader is sourced into a caller that had its own setting. Both
# directions are checked, because a reader that puts the flag back only one way still has the bug.
glob_off=$(
    . "$scratch/agreed/read-sets.sh"
    set -f
    read_set_manifest "$scratch/agreed/sets.txt" "$scratch/agreed"
    case $- in
        *f*) echo off ;;
        *)   echo on ;;
    esac
)
[ "$glob_off" = off ] || fail "a caller that had globbing off got it back on"

glob_on=$(
    . "$scratch/agreed/read-sets.sh"
    set +f
    read_set_manifest "$scratch/agreed/sets.txt" "$scratch/agreed"
    case $- in
        *f*) echo off ;;
        *)   echo on ;;
    esac
)
[ "$glob_on" = on ] || fail "a caller that had globbing on got it back off"

printf 'read-sets adversarial fixtures: PASS\n'
