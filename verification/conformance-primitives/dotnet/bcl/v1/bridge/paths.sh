# Where this bridge's build output lives, and the SDK state that goes with it.
# Sourced by prepare and start, so the two answer the same directory.
#
#     . "$HERE/paths.sh"
#     resolve_bridge_paths "$HERE"
#     # sets BRIDGE_CACHE, BRIDGE_OUT, DOTNET_VERSION_TOKEN, and exports the SDK's state variables
#
# Each checkout gets one build directory, and prepare and start both find the same one.
# conformance-primitives/_shared/cache.sh makes a fresh directory per run, which suits a
# script that builds and runs inside one process. Here preparing and answering are two
# processes the runner starts separately, and the second has to find what the first
# published. So the directory is keyed by the source path instead of by the run. Two
# worktrees of this repository publish to two directories and neither executes the other's
# assembly, which is the rule cache.sh is written to hold; two runs from the same tree
# share one, and prepare takes a lock over it.
#
# The lane cache and the SDK binary are asked of install-toolchain through its print
# queries rather than derived here. That script decides where an SDK is, both queries
# install nothing, and asking it means this file carries no second copy of the rule.

resolve_bridge_paths() {
    _rbp_here="$1"
    _rbp_installer="$_rbp_here/../../../install-toolchain"

    # DCA_VERSION is the token of ../../../versions the lane check selected for
    # this run; it is in the key, so one SDK never executes what another built.
    DOTNET_VERSION_TOKEN="${DCA_VERSION:-default}"
    BRIDGE_CACHE="$("$_rbp_installer" --version "$DOTNET_VERSION_TOKEN" --print-cache)" || return 2
    _rbp_key="$(printf '%s@%s' "$_rbp_here" "$DOTNET_VERSION_TOKEN" | sha256sum | cut -c1-16)" || return 2
    BRIDGE_OUT="$BRIDGE_CACHE/build/bridge-v1/$_rbp_key"

    # Every scrap of SDK state stays inside the cache dir. Without these the CLI writes
    # to $HOME and the project writes bin/ and obj/ into the checkout.
    export DOTNET_CLI_TELEMETRY_OPTOUT=1
    export DOTNET_NOLOGO=1
    export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
    export DOTNET_CLI_HOME="$BRIDGE_CACHE/clihome"
    export NUGET_PACKAGES="$BRIDGE_CACHE/nuget"
}
