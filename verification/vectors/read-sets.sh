# Parser-free validation for the complete vector checksum manifest.
# `check-sums.sh` sources this file so the manifest and the set directories are
# checked against each other before any checksum walk starts.
#
# POSIX sh, no arrays. Set names are directory names and never carry whitespace,
# and a line with a second field is refused, so one plain space-separated string
# holds them safely.
#
#     . "$verification/vectors/read-sets.sh"
#     read_set_manifest "$verification/vectors/sets.txt" "$verification/vectors" || exit 2
#     for name in $DCA_VECTOR_SETS; do ... done
#
# Sets DCA_VECTOR_SETS to every manifest entry, in manifest order. Every
# disagreement between the manifest and the directories is reported, all of
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

    # vectors/ also holds check-sums.sh, sets.txt, read-sets.sh and README.md.
    # Only directories are sets, and every one of them has to be named. The scan
    # uses a glob, so globbing is on for it whatever the caller had set.
    set +f
    for _rsm_dir in "$_rsm_vectors"/*/; do
        [ -d "$_rsm_dir" ] || continue
        _rsm_dir=${_rsm_dir%/}
        _rsm_dir=${_rsm_dir##*/}
        case " $DCA_VECTOR_SETS " in
            *" $_rsm_dir "*) ;;
            *) _rsm_fail "$_rsm_vectors/$_rsm_dir is a set directory and no $_rsm_manifest line names it." ;;
        esac
    done

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
