# Where a lane's toolchain and build output live. Sourced by every lane that
# installs one, so they all answer these the same way.
#
#     . "$HERE/../_shared/cache.sh"
#     resolve_cache_dir jvm
#     # sets DCA_CACHE_DIR
#     resolve_absolute_path ../elsewhere
#     # sets DCA_ABSOLUTE_PATH

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
