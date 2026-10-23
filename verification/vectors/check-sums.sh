#!/bin/sh
# Checks a vector set against the SHA256SUMS file committed beside its
# vectors, and writes that file with --write.
#
#     sh verification/vectors/check-sums.sh                     # every set
#     sh verification/vectors/check-sums.sh v1/baseline/rsa-oaep-envelope-open
#     sh verification/vectors/check-sums.sh --write v1/baseline/rsa-oaep-envelope-open
#
# A hash check runs where a test cannot. Because the vectors define the contract, the
# check that they still carry the bytes they were recorded with must run where
# no replayer does: no JSON parser, no Node, no PHP, nothing but a hash tool.
# The file is plain `sha256sum` format, so
#
#     cd verification/vectors/v1/baseline/rsa-oaep-envelope-open && sha256sum -c SHA256SUMS
#
# answers the same question without this script. Argon2 ships the same pair,
# a `.shasum` per KAT plus check-sums.sh, and it catches what a generator rule
# cannot: a hand edit, a bad merge, a partial checkout.
#
# What a match is worth depends on the phase. This script reads the phase out
# of the set's set.json (by pattern, so this stays parser-free) and prints it
# with every result:
#
#   devel   the bytes match their recorded SHA256SUMS. The set may be maintained
#           by a generator, independent producer or manual recording; this check
#           establishes recorded-byte integrity, not its producer or correctness.
#           These bytes are not frozen.
#   stable  the bytes are frozen. Nothing may rewrite them, so a mismatch is
#           an edit or a bad merge, and changed bytes after a freeze are a new
#           version rather than a regeneration.
#
# SHA256SUMS covers the vectors and not set.json: the manifest declares
# the freeze, and a phase flip must not read as tampering with the bytes.
#
# A file on disk that the sums file does not name fails the set. A vector
# nobody hashed is a vector nobody replays.

set -u

here=$(dirname "$0")
sums_file=SHA256SUMS
write=no

if [ "${1:-}" = "--write" ]; then
    write=yes
    shift
fi

if command -v sha256sum >/dev/null 2>&1; then
    hash_cmd="sha256sum"
    check_cmd="sha256sum -c"
elif command -v shasum >/dev/null 2>&1; then
    hash_cmd="shasum -a 256"
    check_cmd="shasum -a 256 -c"
else
    echo "check-sums.sh: no sha256sum and no shasum on PATH" >&2
    exit 2
fi

# With no arguments, the script walks every set the manifest lists. The manifest
# holds the membership, so a new directory cannot sit in the tree unhashed and
# unreported. For named sets the script runs a focused hash check
# and deliberately makes no full-walk claim.
if [ "$#" -gt 0 ]; then
    sets=$*
    # The script treats a bad set name as an input error rather than a checksum failure. Validate every
    # requested path before walking any one of them, so a valid path followed
    # by a typo cannot
    # report a valid set's bytes and then classify the typo as a mismatch.
    for set_name in $sets; do
        dir=$here/${set_name%/}
        if [ ! -d "$dir" ]; then
            dir=${set_name%/}
        fi
        if [ ! -d "$dir" ]; then
            echo "check-sums.sh: no such set: $set_name" >&2
            exit 2
        fi
    done
else
    # shellcheck source=read-sets.sh
    . "$here/read-sets.sh"
    if ! read_set_manifest "$here/sets.txt" "$here"; then
        exit 2
    fi
    sets="$DCA_VECTOR_SETS"
fi

if [ -z "$sets" ]; then
    echo "check-sums.sh: no vector sets found under $here" >&2
    exit 2
fi

# The phase and the set name are read by pattern rather than parsed, because
# this script is meant to need no parser. A set with no readable phase has no
# byte claim, so the script refuses it rather than reporting an "unmarked" green result.
field_of() {
    sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -1
}

# "1 vector", "6 vectors": a human reads the count every run.
vectors_word() {
    if [ "$1" = 1 ]; then echo "1 vector"; else echo "$1 vectors"; fi
}

# Two counters because the two outcomes are different answers. A set counted in
# `failed` was compared against its sums file and disagreed. A set counted in
# `unverified` has no supported readable phase, so it was never compared to anything: there is
# no byte claim to hold or break, and reporting that as a mismatch tells an
# operator the bytes changed when nothing was read.
failed=0
unverified=0
checked=0

for set_name in $sets; do
    dir=$here/${set_name%/}
    if [ ! -d "$dir" ]; then
        dir=${set_name%/}
    fi
    if [ ! -d "$dir" ]; then
        # The named-path preflight above already exits 2 on this case. A manifest walk
        # cannot reach it because read_set_manifest already checks its dirs.
        echo "check-sums.sh: no such set: $set_name" >&2
        exit 2
    fi

    label=$(basename "$dir")
    if [ ! -f "$dir/set.json" ]; then
        echo "set $label: FAILED"
        echo "  no set.json declares whether these bytes are devel or stable"
        unverified=$((unverified + 1))
        continue
    fi
    label=$(field_of "$dir/set.json" set)
    phase=$(field_of "$dir/set.json" phase)
    [ -n "$label" ] || label=$(basename "$dir")
    case $phase in
        devel|stable) ;;
        *)
            echo "set $label, phase ${phase:-missing}: FAILED"
            echo "  set.json must declare phase devel or stable"
            unverified=$((unverified + 1))
            continue
            ;;
    esac

    checked=$((checked + 1))

    vectors=$(cd "$dir" && ls *.json 2>/dev/null | grep -v '^set\.json$')
    count=$(echo "$vectors" | grep -c . )

    # A set holding nothing but set.json has no bytes to check. Left to run, the
    # hash tool reads stdin instead of a file list, --write records a sums file
    # over nothing, and a check of it passes and prints "0 vectors, every byte matches":
    # a green run that walked no vector at all.
    if [ "$count" -eq 0 ]; then
        echo "set $label, phase $phase: FAILED"
        echo "  no vectors beside set.json - a set with nothing to hash is a set nobody replays"
        failed=$((failed + 1))
        continue
    fi

    if [ "$write" = yes ]; then
        # This branch claims a write, so the script checks the write's status. There is
        # no `set -e` here, and while the status went unread, a run in a read-only directory printed
        # "cannot create SHA256SUMS: Permission denied" and then "wrote
        # SHA256SUMS over 17 vectors" and exited 0, telling an operator recording a
        # new set that the bytes were recorded when no file existed.
        # shellcheck disable=SC2086
        if (cd "$dir" && $hash_cmd $vectors > "$sums_file"); then
            echo "set $label, phase $phase: wrote $sums_file over $(vectors_word "$count")"
        else
            echo "set $label, phase $phase: FAILED"
            echo "  could not write $dir/$sums_file, so the bytes are recorded nowhere"
            failed=$((failed + 1))
        fi
        continue
    fi

    if [ ! -f "$dir/$sums_file" ]; then
        echo "set $label, phase $phase: no $sums_file - run with --write to record the bytes on disk"
        failed=$((failed + 1))
        continue
    fi

    # Every vector on disk is named in the sums file. `sha256sum -c` walks the
    # file and would pass a set that grew a vector nobody hashed.
    unhashed=""
    for vector in $vectors; do
        if ! grep -q "  $vector\$" "$dir/$sums_file"; then
            unhashed="$unhashed $vector"
        fi
    done

    output=$(cd "$dir" && $check_cmd "$sums_file" 2>&1)
    status=$?

    if [ $status -eq 0 ] && [ -z "$unhashed" ]; then
        echo "set $label, phase $phase: $(vectors_word "$count"), every byte matches $sums_file"
    else
        echo "set $label, phase $phase: FAILED"
        echo "$output" | grep -v ': OK$'
        for vector in $unhashed; do
            echo "$vector: not named in $sums_file - a vector nobody hashed"
        done
        failed=$((failed + 1))
    fi

    case $phase in
        stable)
            echo "  stable: the bytes are frozen, so a mismatch is an edit or a bad merge."
            echo "  Changed bytes after a freeze are a new version, not a regeneration."
            ;;
        devel)
            echo "  devel: a match establishes recorded-byte integrity, not producer provenance."
            echo "  The bytes are not frozen; consult the owning producer or recording notes."
            ;;
        *)
            echo "  $phase: the set declares no phase, so a match says only that these"
            echo "  bytes are the ones $sums_file was written over."
            ;;
    esac
done

echo "CHECKED SETS: $checked"

# A set with no readable phase leaves this run short of the walk it was asked
# for, and the runner contract in README.md maps that to exit 2: 0 every stage
# held, 1 a stage failed, 2 the run verified less than it set out
# to. 1 would say these bytes were read and disagreed with their sums file, and
# they were not read at all. When both apply the script exits 2, not 1, because reading a
# partial run as a finished one is the worse mistake, so the script checks this ahead
# of the mismatch count below.
if [ $unverified -gt 0 ]; then
    echo ""
    if [ "$write" = yes ]; then
        echo "RESULT: $unverified set(s) have no usable phase, so nothing was recorded for them."
    else
        echo "RESULT: $unverified set(s) have no usable phase, so their bytes were checked against nothing."
    fi
    exit 2
fi

if [ "$write" = yes ]; then
    if [ $failed -gt 0 ]; then
        echo ""
        echo "RESULT: $failed set(s) were not written."
        exit 1
    fi
    exit 0
fi

if [ $failed -gt 0 ]; then
    echo ""
    echo "RESULT: $failed set(s) do not match their $sums_file."
    exit 1
fi

echo ""
echo "RESULT: every set carries the bytes its $sums_file was written over."
