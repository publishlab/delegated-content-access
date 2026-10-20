# Where a lane's toolchain and build output live, and which runtime version it
# installs. Sourced by every lane that installs one, so they all answer these
# the same way.
#
#     . "$HERE/../_shared/cache.sh"
#     resolve_cache_dir jvm
#     # sets DCA_CACHE_DIR
#     resolve_absolute_path ../elsewhere
#     # sets DCA_ABSOLUTE_PATH
#     resolve_version_pin "$HERE/versions" 24
#     # sets DCA_VERSION_TOKEN and DCA_VERSION_RELEASE (runtime versions, below)

# The cache dir for one lane. There is one cache root for this project and the
# lanes are leaves under it, so the argument is the leaf name and nothing else:
# a lane runs on its own and the installer that calls this already knows which
# lane it is, so an environment variable naming the lane would repeat what the
# caller just passed.
#
# The root, in three outcomes, in order, and no fourth:
#
#   1. $DCA_CACHE, if it is set. An operator who names a directory gets that
#      directory, on any OS. The per-invocation --cache-root flag is the other
#      way in and reaches here as the caller passing what it was given instead
#      of calling this at all.
#   2. the OS cache directory. $XDG_CACHE_HOME/dca when it is set, otherwise
#      ~/.cache/dca on Linux and ~/Library/Caches/dca on macOS.
#   3. refuse, naming DCA_CACHE.
#
# The third case is the point. Falling back to a guessed path when neither a
# variable nor a known OS cache is available writes a few hundred megabytes
# somewhere nobody looks, and on a machine with no HOME it writes to /.cache.
# A lane that cannot say where its cache belongs has not earned the download.

resolve_cache_dir() {
    _rcd_lane="$1"

    if [ -n "${DCA_CACHE:-}" ]; then
        DCA_CACHE_DIR="$DCA_CACHE/$_rcd_lane"
        return 0
    fi

    # XDG_CACHE_HOME is honoured on every OS, because an operator sets it
    # deliberately.
    if [ -n "${XDG_CACHE_HOME:-}" ]; then
        DCA_CACHE_DIR="$XDG_CACHE_HOME/dca/$_rcd_lane"
        return 0
    fi

    if [ -z "${HOME:-}" ]; then
        echo "DCA_CACHE is unset, XDG_CACHE_HOME is unset, and so is HOME." >&2
        echo "There is no cache directory to fall back to. Set DCA_CACHE." >&2
        exit 2
    fi

    case "$(uname -s)" in
        Linux)  DCA_CACHE_DIR="$HOME/.cache/dca/$_rcd_lane" ;;
        Darwin) DCA_CACHE_DIR="$HOME/Library/Caches/dca/$_rcd_lane" ;;
        *)
            echo "$(uname -s) has no cache directory this script knows, and" >&2
            echo "DCA_CACHE is unset. Set DCA_CACHE to say where the toolchains go." >&2
            exit 2
            ;;
    esac
}

# A path flag's value, resolved to an absolute path against the directory the
# caller ran from.
#
#     resolve_absolute_path "$2"
#     base="$DCA_ABSOLUTE_PATH"
#
# --base and --cache-root are read in one place and used in several, and those
# places do not share a working directory. An installer checks --base against
# the directory it was started in and prints the path it settled on; the lane
# wrapper then hands that path to a compiler it runs from inside the lane's
# package, so `cd v1 && go build` under a relative --base looks for a toolchain
# under v1 and reports the miss as a lane that did not compile. The value is
# resolved to an absolute path where it is read, once, so every later reader
# sees the directory the operator meant.
#
# This is a string operation and never visits the filesystem, because the print
# queries have to print a path for a directory that is not there yet:
# --print-bin names where a binary would be, and resolving through the
# filesystem would turn a query into an installation check. Whether a --base
# directory really holds a toolchain is a separate question, asked by the
# installer, which says which part was missing. This has one consequence:
# `--base ""` now resolves to the caller's own directory and is refused there by
# name, where before it read as no --base at all and the run quietly used the
# pinned path.
resolve_absolute_path() {
    case "$1" in
        /*) DCA_ABSOLUTE_PATH="$1" ;;
        *)  DCA_ABSOLUTE_PATH="$PWD/$1" ;;
    esac
}

# Where one run's build output goes.
#
#     resolve_build_dir "$cache" v1
#     trap 'rm -rf "$DCA_BUILD_DIR"' EXIT
#     # sets DCA_BUILD_DIR, a fresh directory under <cache>/build/<lane>
#
# Each run builds into a directory of its own. A build directory named for the
# lane alone is one directory for every checkout on the machine and for every
# run of the lane at once, because one cache dir serves all of them: ~/.cache is
# shared across containers, and a repository with two worktrees has two source
# trees pointing at it. A lane that compiles into a fixed name reads back class
# files or an assembly built somewhere else and reports the answer as its own,
# which is the one thing a conformance run must not do. Two runs proved it
# before this function existed: a second tree whose sources were older than the
# stamp the first tree left replayed the first tree's classes and exited 0, and
# two concurrent runs from two trees each replayed whichever build landed last.
#
# The rule came from the Go lane's fresh per-run binary directory, and every
# lane that compiles now takes it from here, under the lane's own cache
# rather than in whatever TMPDIR the environment holds. It takes the cache dir
# as an argument because the installer owns that path and the wrapper asks it
# rather than rebuilding it here.
#
# The cost is one full compile per run: about a second for javac over this
# lane's four sources, and about a second for `dotnet build` over a project with
# no PackageReference to restore. Reusing a compile across runs is worth less
# than knowing which sources produced the classes behind the answer.
resolve_build_dir() {
    _rbd_root="$1/build/$2"
    mkdir -p "$_rbd_root" || exit 2
    DCA_BUILD_DIR="$(mktemp -d "$_rbd_root/run.XXXXXXXX")" || exit 2
}

# ---- runtime versions --------------------------------------------------------
#
# Each runtime lists the versions it runs in `<runtime>/versions`, beside its
# installer, one token per line:
#
#     24 24.21.0 default
#     22 22.23.3 default
#
# The first field is the token an operator types (`--version 24`), the second
# the release the installer pins for it, and the third says whether a run with
# no version input runs it (`default`) or only a run that names it or asks for
# `all` (`listed`). A line starting with `#` is a comment. The installer keeps
# the download and the checksum for each token; this file says which tokens
# exist, so adding a version is one line here and one pin there, and retiring
# one is deleting both.
#
# A token is also a file-name part (`<record>.<token>`) and a label
# (`node/openssl@24`), so it holds only letters, digits, `.`, `_` and `-`, and
# `default` and `all` are the two selector words rather than tokens.

# The list, validated, one `<token> <release> <state>` line per entry in file
# order, on stdout. Returns 2 after naming every problem on stderr.
read_version_list() {
    if [ ! -f "$1" ] || [ ! -r "$1" ]; then
        echo "no readable version list at $1, so no runtime version can be named." >&2
        return 2
    fi
    awk -v file="$1" '
        /^[ \t]*(#|$)/ { next }
        {
            if (NF != 3) { printf "%s:%d: \"%s\" is not <token> <release> <default|listed>.\n", file, NR, $0 > "/dev/stderr"; bad = 1; next }
            if ($1 !~ /^[0-9A-Za-z][0-9A-Za-z._-]*$/ || $1 == "default" || $1 == "all") {
                printf "%s:%d: \"%s\" is not a token; a token is letters, digits, dot, underscore and dash, and not default or all.\n", file, NR, $1 > "/dev/stderr"; bad = 1; next
            }
            if ($3 != "default" && $3 != "listed") {
                printf "%s:%d: token %s is \"%s\", and a token is default or listed.\n", file, NR, $1, $3 > "/dev/stderr"; bad = 1; next
            }
            if ($1 in seen) { printf "%s:%d: token %s is listed twice.\n", file, NR, $1 > "/dev/stderr"; bad = 1; next }
            seen[$1] = 1
            lines[++n] = $1 " " $2 " " $3
        }
        END {
            if (bad) exit 2
            if (n == 0) { printf "%s lists no version.\n", file > "/dev/stderr"; exit 2 }
            for (i = 1; i <= n; i++) print lines[i]
        }
    ' "$1"
}

# Which tokens one version input selects, in list order.
#
#     resolve_version_selection <runtime>/versions default|all|<token>
#     # sets DCA_VERSION_TOKENS, space separated
#
# `default` selects every default token, `all` every token, and a token itself.
# Returns 3, with nothing printed, when the list does not name that token, so a
# suite can report the lane as not selected and a lane check can refuse; 2
# after a message when the list or the input cannot be read.
resolve_version_selection() {
    DCA_VERSION_TOKENS=""
    _rvs_lines=$(read_version_list "$1") || return 2
    case "$2" in
        default) DCA_VERSION_TOKENS=$(printf '%s\n' "$_rvs_lines" | awk '$3 == "default" { printf "%s%s", sep, $1; sep = " " }') ;;
        all)     DCA_VERSION_TOKENS=$(printf '%s\n' "$_rvs_lines" | awk '{ printf "%s%s", sep, $1; sep = " " }') ;;
        "")
            echo "the version input is empty; give default, all or a token from $1." >&2
            return 2 ;;
        *)
            DCA_VERSION_TOKENS=$(printf '%s\n' "$_rvs_lines" | awk -v want="$2" '$1 == want { print $1 }')
            [ -n "$DCA_VERSION_TOKENS" ] || return 3 ;;
    esac
    return 0
}

# The one pin an installer, or a single-run entry point, installs or answers.
#
#     resolve_version_pin <runtime>/versions default|<token>
#     # sets DCA_VERSION_TOKEN and DCA_VERSION_RELEASE
#
# `default` takes the first default line, which is the newest by the order the
# lists are kept in. `all` is refused, because one install is one version. A
# token the list does not name is refused by name with the tokens it does.
resolve_version_pin() {
    DCA_VERSION_TOKEN=""
    DCA_VERSION_RELEASE=""
    _rvp_lines=$(read_version_list "$1") || return 2
    case "$2" in
        all)
            echo "one install or run takes one version, and all names every token in $1." >&2
            echo "A lane check runs each of them: <lane>/check --version all." >&2
            return 2 ;;
        default|"")
            _rvp_line=$(printf '%s\n' "$_rvp_lines" | awk '$3 == "default" { print; exit }')
            if [ -z "$_rvp_line" ]; then
                echo "$1 marks no token default, so default names no version." >&2
                return 2
            fi ;;
        *)
            _rvp_line=$(printf '%s\n' "$_rvp_lines" | awk -v want="$2" '$1 == want { print; exit }')
            if [ -z "$_rvp_line" ]; then
                echo "version $2 is not listed in $1, which lists: $(printf '%s\n' "$_rvp_lines" | awk '{ printf "%s%s", sep, $1; sep = " " }')." >&2
                echo "A version runs only once its runtime lists it with a pin. Refused; nothing was installed or run." >&2
                return 2
            fi ;;
    esac
    DCA_VERSION_TOKEN=${_rvp_line%% *}
    _rvp_rest=${_rvp_line#* }
    DCA_VERSION_RELEASE=${_rvp_rest%% *}
    return 0
}
