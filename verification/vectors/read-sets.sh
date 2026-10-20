# Parser-free validation for the complete vector checksum manifest.
# `check-sums.sh` sources this file so the manifest and the set directories are
# checked against each other before any checksum walk starts.
#
# POSIX sh, no arrays. Set paths are restricted to simple root directory names
# or exact-depth v1/baseline/<item>, v1/profiles/<profile> and
# v1/experiments/<experiment> paths;
# none carry whitespace. A line
# with a second field is refused, so one space-separated string holds them.
#
#     . "$verification/vectors/read-sets.sh"
#     read_set_manifest "$verification/vectors/sets.txt" "$verification/vectors" || exit 2
#     for name in $DCA_VECTOR_SETS; do ... done
#
# Sets DCA_VECTOR_SETS to every manifest entry, in manifest order. Entries may
# name direct child sets or exact-depth v1/baseline/<item>/,
# v1/profiles/<profile>/ and v1/experiments/<experiment>/ packages. Sets are
# flat, and any file or directory outside that layout is refused by path. Every
# disagreement between the manifest and the package directories is reported, all of
# them together rather than only the first, and then it returns 2: the run
# would verify less than it set out to, which is what 2 means everywhere else
# in this tree. It returns rather than exits because it is sourced: an outside
# implementer who embeds this reader in a larger script has that script killed
# by an `exit` here, so `|| exit 2` at the call site is where a run ends.
#
# It also leaves the caller's shell as it found it. Splitting a manifest line
# needs globbing off and the directory scan needs it on, so the flag is read on
# entry and put back before the return rather than turned on and left there.

read_set_manifest() {
    case $- in
        *f*) _rsm_glob_was=off ;;
        *)   _rsm_glob_was=on ;;
    esac
    _rsm_read "$@"
    _rsm_status=$?
    case "$_rsm_glob_was" in
        off) set -f ;;
        on)  set +f ;;
    esac
    return "$_rsm_status"
}

_rsm_read() {
    DCA_VECTOR_SETS=""
    _rsm_broken=0

    if [ $# -ne 2 ]; then
        echo "read_set_manifest: expected 2 arguments (manifest and vectors directory), got $#." >&2
        echo "RESULT: the walk is undefined. Nothing ran." >&2
        return 2
    fi

    _rsm_manifest="$1"
    _rsm_vectors="$2"

    if [ ! -f "$_rsm_manifest" ]; then
        echo "$_rsm_manifest: not there. Nothing says which sets this run walks." >&2
        echo "RESULT: the walk is undefined. Nothing ran." >&2
        return 2
    fi

    while IFS= read -r _rsm_line || [ -n "$_rsm_line" ]; do
        set -f
        # The format relies on word splitting: one whitespace-separated field.
        # shellcheck disable=SC2086
        set -- $_rsm_line
        set +f
        [ $# -gt 0 ] || continue
        case "$1" in
            '#'*) continue ;;
        esac

        if [ $# -ne 1 ]; then
            _rsm_fail "$_rsm_manifest: $# field(s) where 1 is expected: \"$_rsm_line\""
            continue
        fi

        case "$1" in
            v1)
                _rsm_fail "$_rsm_manifest has an invalid set path: $1 (container)"
                continue ;;
            v1/baseline/*)
                _rsm_package=${1#v1/baseline/}
                case "$_rsm_package" in
                    ''|*[!a-zA-Z0-9._-]*|.|..)
                        _rsm_fail "$_rsm_manifest has an invalid set path: $1"
                        continue ;;
                esac
                ;;
            v1/profiles/dca-profile-*)
                _rsm_package=${1#v1/profiles/dca-profile-}
                case "$_rsm_package" in
                    ''|*[!a-zA-Z0-9._-]*|.|..)
                        _rsm_fail "$_rsm_manifest has an invalid set path: $1"
                        continue ;;
                esac
                ;;
            v1/experiments/*)
                _rsm_package=${1#v1/experiments/}
                case "$_rsm_package" in
                    ''|*[!a-zA-Z0-9._-]*|.|..)
                        _rsm_fail "$_rsm_manifest has an invalid set path: $1"
                        continue ;;
                esac
                ;;
            *[!a-zA-Z0-9._-]*|.|..) _rsm_fail "$_rsm_manifest has an invalid set path: $1"; continue ;;
        esac

        # A set may appear on only one manifest line. A set named twice would
        # be hashed twice, and the walk would report two answers for the same
        # directory.
        case " $DCA_VECTOR_SETS " in
            *" $1 "*)
                _rsm_fail "$_rsm_manifest names $1 more than once, and a set is walked one way."
                continue
                ;;
        esac

        DCA_VECTOR_SETS="$DCA_VECTOR_SETS $1"
        [ -d "$_rsm_vectors/$1" ] \
            || _rsm_fail "$_rsm_manifest names $1, and $_rsm_vectors/$1 is not a directory."
    done < "$_rsm_manifest"

    # vectors/ also holds scripts and documentation. Root child directories
    # other than the v1/ container and exact-depth packages must be named.
    # Globbing is on for the scan whatever the caller had set.
    set +f
    for _rsm_dir in "$_rsm_vectors"/*/; do
        [ -d "$_rsm_dir" ] || continue
        _rsm_dir=${_rsm_dir%/}
        _rsm_dir=${_rsm_dir##*/}
        [ "$_rsm_dir" = v1 ] && continue
        case " $DCA_VECTOR_SETS " in
            *" $_rsm_dir "*) ;;
            *) _rsm_fail "$_rsm_vectors/$_rsm_dir is a set directory and no $_rsm_manifest line names it." ;;
        esac
    done
    for _rsm_dir in "$_rsm_vectors"/v1/baseline/*/; do
        [ -d "$_rsm_dir" ] || continue
        _rsm_dir=${_rsm_dir%/}
        _rsm_dir=${_rsm_dir##*/}
        case " $DCA_VECTOR_SETS " in
            *" v1/baseline/$_rsm_dir "*) ;;
            *) _rsm_fail "$_rsm_vectors/v1/baseline/$_rsm_dir is a baseline package and no $_rsm_manifest line names it." ;;
        esac
    done
    for _rsm_dir in "$_rsm_vectors"/v1/profiles/*/; do
        [ -d "$_rsm_dir" ] || continue
        _rsm_dir=${_rsm_dir%/}
        _rsm_dir=${_rsm_dir##*/}
        case " $DCA_VECTOR_SETS " in
            *" v1/profiles/$_rsm_dir "*) ;;
            *) _rsm_fail "$_rsm_vectors/v1/profiles/$_rsm_dir is a profile package and no $_rsm_manifest line names it." ;;
        esac
    done

    for _rsm_dir in "$_rsm_vectors"/v1/experiments/*/; do
        [ -d "$_rsm_dir" ] || continue
        _rsm_dir=${_rsm_dir%/}
        _rsm_dir=${_rsm_dir##*/}
        case " $DCA_VECTOR_SETS " in
            *" v1/experiments/$_rsm_dir "*) ;;
            *) _rsm_fail "$_rsm_vectors/v1/experiments/$_rsm_dir is an experiment package and no $_rsm_manifest line names it." ;;
        esac
    done

    # The scans above look only where sets.txt may point, and `check-sums.sh`
    # hashes only the top-level files of a set. A payload anywhere else is data
    # no walk reads: a test put v1/extras/hidden/vector.json,
    # v1/baseline/stray.json and a nested directory in a listed package beside
    # one listed package, and the walk printed "CHECKED SETS: 1" and exited 0.
    # So the reader walks the whole tree with find and names every path off
    # this layout:
    #
    #     <root-set>/<file>                                     root set, flat
    #     v1/<baseline|profiles|experiments>/<package>/<file>   package, flat
    #
    # Files beside sets.txt are the tooling, except a JSON file or SHA256SUMS,
    # which is payload-shaped. Of an off-layout directory only the top one is
    # named, and every file under it is named too.
    _rsm_offlayout=$(
        cd "$_rsm_vectors" || exit 0
        {
            find . -mindepth 1 -type d -print | sed 's|^\./|d/|'
            find . -mindepth 1 ! -type d -print | sed 's|^\./|f/|'
        } | awk -F/ '
            function group(g) { return g == "baseline" || g == "profiles" || g == "experiments" }
            {
                kind = $1; depth = NF - 1; path = substr($0, 3)
                if ($2 == "v1") {
                    if (kind == "d") {
                        if ((depth == 2 || depth == 3) && group($3)) next
                        if (depth == 2 || (depth == 4 && group($3))) print "dir " path
                        next
                    }
                    if (depth == 4 && group($3)) next
                    print (depth == 2 ? "stranded " : "file ") path
                    next
                }
                if (depth == 1) {
                    if (kind == "f" && ($2 ~ /\.json$/ || $2 == "SHA256SUMS")) print "file " path
                    next
                }
                if (depth == 2 && kind == "f") next
                if (kind == "f") print "file " path
                else if (depth == 2) print "dir " path
            }' | LC_ALL=C sort -k2
    )
    while IFS= read -r _rsm_line; do
        case "$_rsm_line" in
            'stranded '*)
                _rsm_fail "$_rsm_vectors/${_rsm_line#stranded } is stranded in the v1 container; move it into a named package." ;;
            'dir '*)
                _rsm_fail "$_rsm_vectors/${_rsm_line#dir } sits outside the vector layout, so no walk reads anything under it." ;;
            'file '*)
                _rsm_fail "$_rsm_vectors/${_rsm_line#file } sits outside the vector layout, so no walk hashes or replays it." ;;
        esac
    done <<EOF
$_rsm_offlayout
EOF
    if [ -n "$_rsm_offlayout" ]; then
        echo "The vector layout is <root-set>/<file> and v1/<baseline|profiles|experiments>/<package>/<file>; move each path above into a package that $_rsm_manifest names." >&2
    fi

    if [ -z "$DCA_VECTOR_SETS" ]; then
        _rsm_fail "$_rsm_manifest names no sets, so this run would walk nothing."
    fi

    if [ "$_rsm_broken" -gt 0 ]; then
        echo "RESULT: $_rsm_manifest and $_rsm_vectors disagree. Nothing ran." >&2
        return 2
    fi
    return 0
}

_rsm_fail() {
    echo "$1" >&2
    _rsm_broken=$((_rsm_broken + 1))
}
