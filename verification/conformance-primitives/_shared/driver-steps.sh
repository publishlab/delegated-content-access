# The whole of what a lane check runs, with the record that follows it. Sourced
# after DCA_LANE, DCA_RECORD and DCA_VERSION_SELECTION are set, beside a
# `lane_runtime` function that installs the selected version and observes it:
#
#     . "$HERE/../../_shared/driver-steps.sh"
#     lane_runtime() { ... }        # below, at run_lane_versions
#     run_lane_versions "$HERE/.."
#     exit "$DCA_LANE_STATUS"
#
# run_lane_versions runs run_driver_steps once per selected runtime version and
# writes one record per run with write_driver_record.
#
# A lane check runs one step: the case corpus through this lane's own operation
# bridge, one set at a time. The corpus groups its cases into sets by the
# operations they ask for, so a lane that answers four of the seven operations
# still holds the sets it can answer, and the run names the sets nobody asked
# it.
#
# The steps take no argument. A lane check resolves the selected version's
# toolchain to observe and print its version; the steps run through that lane's
# bridge.json, whose prepare step installs the same version from DCA_VERSION,
# so nothing a check resolves for itself narrows what they answer.
#
# `_shared/driver/select-sets.mjs` names the corpus sets and says which of them
# this lane declares every operation for. `_shared/driver/run.mjs --set` then
# answers one set, as a child process whose exit code is read back: the same
# 0/1/2 `RUN_EXIT` names run.mjs exits with. Nothing here reads an expected
# value, decides a case or writes a parser.
#
# This file finds the driver from its own location (DCA_DRIVER_STEPS_HERE,
# below): a file under _shared/ reaches its own sibling directly rather than
# going out through the caller's HERE and back in again.
DCA_DRIVER_STEPS_HERE="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The version list reader lives beside the cache rule, because the installers
# read the same lists.
# shellcheck source=cache.sh
. "$DCA_DRIVER_STEPS_HERE/cache.sh"

# DCA_JS names the JavaScript runtime that runs the driver itself. This file and
# conformance-primitives/run both read it and map it the same two ways: node by default,
# `deno run -A` for deno. The mapping is duplicated here rather than sourced from
# run, because run is an executable entry point: it self-checks and execs.
: "${DCA_JS:=node}"
case "$DCA_JS" in
    node) DCA_DRIVER_RUN="node" ;;
    deno) DCA_DRIVER_RUN="deno run -A" ;;
    *)
        echo "conformance-primitives/_shared/driver-steps.sh: DCA_JS is \"$DCA_JS\"; this runs under node or deno, the same runtimes conformance-primitives/run maps." >&2
        DCA_DRIVER_RUN=""
        ;;
esac

# Which corpus sets this lane can be asked, printed one per line by the driver
# that already reads both the corpus and the lane's manifest.
DCA_SET_SELECTOR="$DCA_DRIVER_STEPS_HERE/driver/select-sets.mjs"

# One set's exit code, folded into DCA_SETS_STATUS under the rule the exit codes
# carry everywhere here: 2 beats 1 beats 0, and anything outside 0/1/2 is 2.
fold_set_status() {
    case "$1" in
        0) ;;
        1) [ "$DCA_SETS_STATUS" = 2 ] || DCA_SETS_STATUS=1 ;;
        *) DCA_SETS_STATUS=2 ;;
    esac
}

# The case corpus through this lane's own bridge, set by set. Sets
# DCA_SETS_STATUS and appends to DCA_DRIVER_ROWS one row per operation the
# lane's bridge.json declares, `operation=<name> member=<member>`, then one row
# per set: `set=<name> status=held|disagreed|incomplete|unsupported`.
#
# The operation rows say which member of the binding answers each operation,
# as the selector read it from bridge.json. They are record metadata: no bridge
# is asked who answered, and the rows reach no exit code.
#
# A set asking for an operation this lane has not declared is unsupported: no
# bridge starts for it, its row says so, and it reaches no exit code. A lane
# that answered nothing would otherwise exit 0 over cases nobody ran.
#
# One process and one judged run per set, so a disagreement in one set is
# reported against that row alone.
answer_corpus_sets() {
    DCA_SETS_STATUS=0
    if [ -z "$DCA_DRIVER_RUN" ]; then
        DCA_SETS_STATUS=2
        return
    fi

    dca_ds_selection=$(mktemp) || {
        echo "could not create a corpus-set selection file" >&2
        DCA_SETS_STATUS=2
        return
    }
    dca_ds_select_status=0
    # shellcheck disable=SC2086
    $DCA_DRIVER_RUN "$DCA_SET_SELECTOR" "$DCA_LANE" > "$dca_ds_selection" || dca_ds_select_status=$?
    if [ "$dca_ds_select_status" -ne 0 ]; then
        rm -f "$dca_ds_selection"
        DCA_SETS_STATUS=2
        return
    fi

    dca_ds_operations=""
    dca_ds_sets=""
    while IFS= read -r dca_ds_line; do
        [ -n "$dca_ds_line" ] || continue
        # Three fields, `operation <name> <member>`: one declared operation
        # and the member that answers it. The selector prints them after the
        # set lines, and the record carries them ahead of the set rows.
        case "$dca_ds_line" in
            "operation "*" "*)
                dca_ds_rest=${dca_ds_line#operation }
                dca_ds_row="operation=${dca_ds_rest%% *} member=${dca_ds_rest#* }"
                dca_ds_operations="$dca_ds_operations$dca_ds_row
"
                continue ;;
        esac
        # Two fields: the set name and whether this lane declares every
        # operation it asks for.
        dca_ds_name=${dca_ds_line%% *}
        dca_ds_support=${dca_ds_line#* }
        if [ "$dca_ds_support" = unsupported ]; then
            dca_ds_word=unsupported
        else
            dca_ds_one=0
            # shellcheck disable=SC2086
            $DCA_DRIVER_RUN "$DCA_DRIVER_STEPS_HERE/driver/run.mjs" "$DCA_LANE" --set "$dca_ds_name" \
                || dca_ds_one=$?
            case $dca_ds_one in
                0) dca_ds_word=held ;;
                1) dca_ds_word=disagreed ;;
                *) dca_ds_word=incomplete ;;
            esac
            fold_set_status "$dca_ds_one"
        fi
        echo "== corpus set $dca_ds_name through the $DCA_LANE bridge: $dca_ds_word ==" >&2
        dca_ds_sets="${dca_ds_sets}set=$dca_ds_name status=$dca_ds_word
"
    done < "$dca_ds_selection"
    rm -f "$dca_ds_selection"
    DCA_DRIVER_ROWS="${DCA_DRIVER_ROWS:-}$dca_ds_operations$dca_ds_sets"

    # A selection that named no set at all leaves a lane claiming a hold over
    # nothing, so it is incomplete instead.
    if [ -z "$dca_ds_sets" ]; then
        echo "the set selector named no corpus set, so this lane answered nothing" >&2
        DCA_SETS_STATUS=2
    fi
}

# The one entry point every lane check shares: answer the corpus set by set and
# leave the exit code in DCA_WALK_STATUS. Every caller ends `exit
# "$DCA_WALK_STATUS"` under `set -euo pipefail`, so this always sets it.
run_driver_steps() {
    answer_corpus_sets
    DCA_WALK_STATUS=$DCA_SETS_STATUS
}

# The record a run writes: lane=, then, when the run had a runtime version,
# version= (the token) and runtime= (what the installed binary said it is),
# then DCA_DRIVER_ROWS (the operation= rows in manifest order and the set=
# rows in corpus order, as the step above appended them), then the exit line,
# written from the same DCA_WALK_STATUS the caller is about to exit with, so
# the record and the exit status always match.
#
#     lane=php/openssl
#     version=8.3
#     runtime=8.3.32
#     operation=decode-base64url member=lane
#     operation=hkdf-sha256 member=hash
#     ...
#     set=encoding status=held
#     set=aes-gcm-128 status=held
#     set=hkdf status=unsupported
#     exit=0
#
# The version lines come from DCA_RUN_VERSION and DCA_RUNTIME_OBSERVED, which
# run_lane_versions sets per run. A run with a version and no observed runtime
# writes nothing: the record would name a version nobody saw answer.
#
# Written only when the caller set DCA_RECORD, the file path, and only once
# DCA_WALK_STATUS is final, so the caller calls this right before its own exit.
#
# The content is built whole, written to a sibling temp path and moved onto the
# named path, so a reader opening that path finds either the previous record or
# this complete one, and never a half-written record that would refold into an
# answer nobody computed.
#
# It returns 1 rather than exiting, the way everything else here returns, and
# the caller turns that into the walk's status.
write_driver_record() {
    if [ -z "${DCA_LANE:-}" ]; then
        echo "a record was asked for at $DCA_RECORD and no lane name was set, so nothing here can say" >&2
        echo "which lane the record would be about. Nothing was written." >&2
        return 1
    fi
    if [ -n "${DCA_RUN_VERSION:-}" ] && [ -z "${DCA_RUNTIME_OBSERVED:-}" ]; then
        echo "a record for version $DCA_RUN_VERSION was asked for at $DCA_RECORD and no runtime version" >&2
        echo "was observed from the installed binary, so nothing was written." >&2
        return 1
    fi
    if { printf 'lane=%s\n' "$DCA_LANE"
         if [ -n "${DCA_RUN_VERSION:-}" ]; then
             printf 'version=%s\n' "$DCA_RUN_VERSION"
             printf 'runtime=%s\n' "$DCA_RUNTIME_OBSERVED"
         fi
         printf '%s' "${DCA_DRIVER_ROWS:-}"
         printf 'exit=%s\n' "$DCA_WALK_STATUS"
       } > "$DCA_RECORD.tmp" && mv "$DCA_RECORD.tmp" "$DCA_RECORD"; then
        return 0
    fi
    echo "the run was asked to record its result to $DCA_RECORD and could not write it." >&2
    echo "A run that cannot leave the record it was asked for verified less than it was asked to." >&2
    return 1
}

# The record of a version the runtime lists and this binding cannot run. It
# carries the reason instead of operation and set rows, and exit 0: the binding states the
# fact, the same way a set it does not declare is unsupported rather than a
# failure, and the aggregate prints it as refused, a word kept apart from the
# operation word `unsupported`.
#
#     lane=php/openssl
#     version=7.3
#     status=refused
#     reason=ext/openssl in 7.3 has no openssl_pkey_derive
#     exit=0
write_refused_record() {
    if [ -z "${DCA_LANE:-}" ] || [ -z "${DCA_RUN_VERSION:-}" ] || [ -z "$1" ]; then
        echo "a refused record needs a lane, a version and a reason, so nothing was written to $DCA_RECORD." >&2
        return 1
    fi
    case "$1" in
        *'
'*) echo "a refusal reason is one line, so nothing was written to $DCA_RECORD." >&2
            return 1 ;;
    esac
    if { printf 'lane=%s\n' "$DCA_LANE"
         printf 'version=%s\n' "$DCA_RUN_VERSION"
         printf 'status=refused\n'
         printf 'reason=%s\n' "$1"
         printf 'exit=0\n'
       } > "$DCA_RECORD.tmp" && mv "$DCA_RECORD.tmp" "$DCA_RECORD"; then
        return 0
    fi
    echo "the refusal of version $DCA_RUN_VERSION could not be recorded at $DCA_RECORD." >&2
    return 1
}

# ---- one run per runtime version ---------------------------------------------
#
# A lane check runs the corpus once per selected runtime version: the same
# node/openssl lane on Node 24 and on Node 22 is two runs and two records that
# differ in the version lines. The version input is DCA_VERSION_SELECTION,
# which the check sets from --version, else DCA_VERSION, else `default`:
#
#     default   every token the runtime's list marks default
#     all       every token the list names
#     <token>   that token; one the list does not name is refused with exit 2
#               before anything is installed
#
#     run_lane_versions <runtime dir>
#     # sets DCA_LANE_STATUS, 2 beats 1 beats 0 across the runs
#
# For each token it exports DCA_VERSION=<token>, so the prepare step and the
# answering process the driver starts ask the installer for that version, and
# calls the check's own `lane_runtime <token>`, which installs that version,
# prints a banner and sets DCA_RUNTIME_OBSERVED from the installed binary's own
# answer (`php -r 'echo PHP_VERSION;'`, `node --version`), never from the list.
# A lane_runtime that fails, or observes nothing, makes that run incomplete and
# leaves no record, and the next token still runs.
#
# A check may also define `lane_version_refusal <token>`, printing one line
# when this binding cannot run a version its runtime lists. That run is then
# refused: nothing is installed, and its record says why. No binding defines it
# today; a binding names such a version there, not in a list of its own.
#
# DCA_RECORD, when set, names the record of a single-token run. A selection of
# several tokens writes `<DCA_RECORD>.<token>` for each, so every
# (lane, version) pair has a path of its own.
run_lane_versions() {
    dca_lv_list="$(cd "$1" && pwd)/versions"
    dca_lv_record="${DCA_RECORD:-}"
    DCA_LANE_STATUS=0
    dca_lv_status=0
    resolve_version_selection "$dca_lv_list" "${DCA_VERSION_SELECTION:-default}" || dca_lv_status=$?
    case "$dca_lv_status" in
        0) ;;
        3) resolve_version_selection "$dca_lv_list" all
           echo "$DCA_LANE: version ${DCA_VERSION_SELECTION} is not listed in $dca_lv_list, which lists: $DCA_VERSION_TOKENS." >&2
           echo "A version runs only once its runtime lists it with a pin. Refused; nothing ran." >&2
           DCA_LANE_STATUS=2
           return 0 ;;
        *) DCA_LANE_STATUS=2
           return 0 ;;
    esac
    # shellcheck disable=SC2086
    set -- $DCA_VERSION_TOKENS
    if [ $# -eq 0 ]; then
        echo "$DCA_LANE: $dca_lv_list selects no token for ${DCA_VERSION_SELECTION}, so nothing ran." >&2
        DCA_LANE_STATUS=2
        return 0
    fi
    dca_lv_count=$#

    for dca_lv_token in "$@"; do
        DCA_RUN_VERSION=$dca_lv_token
        DCA_RUNTIME_OBSERVED=""
        DCA_DRIVER_ROWS=""
        DCA_WALK_STATUS=2
        export DCA_VERSION=$dca_lv_token
        if [ -z "$dca_lv_record" ]; then
            DCA_RECORD=""
        elif [ "$dca_lv_count" -eq 1 ]; then
            DCA_RECORD=$dca_lv_record
        else
            DCA_RECORD="$dca_lv_record.$dca_lv_token"
        fi
        echo "== $DCA_LANE, version $dca_lv_token ==" >&2

        dca_lv_reason=""
        if declare -F lane_version_refusal >/dev/null; then
            dca_lv_reason=$(lane_version_refusal "$dca_lv_token") || dca_lv_reason=""
        fi
        if [ -n "$dca_lv_reason" ]; then
            echo "== $DCA_LANE@$dca_lv_token: refused: $dca_lv_reason ==" >&2
            DCA_WALK_STATUS=0
            if [ -n "$DCA_RECORD" ]; then
                write_refused_record "$dca_lv_reason" || DCA_WALK_STATUS=2
            fi
        elif ! lane_runtime "$dca_lv_token"; then
            echo "$DCA_LANE@$dca_lv_token: no usable runtime, so nothing was verified for this version." >&2
            DCA_WALK_STATUS=2
        elif [ -z "$DCA_RUNTIME_OBSERVED" ]; then
            echo "$DCA_LANE@$dca_lv_token: the installed runtime did not say which version it is, so nothing was verified." >&2
            DCA_WALK_STATUS=2
        else
            echo "== runtime observed: $DCA_RUNTIME_OBSERVED ==" >&2
            run_driver_steps
            if [ -n "$DCA_RECORD" ]; then
                write_driver_record || DCA_WALK_STATUS=2
            fi
        fi
        case "$DCA_WALK_STATUS" in
            0) ;;
            1) [ "$DCA_LANE_STATUS" = 2 ] || DCA_LANE_STATUS=1 ;;
            *) DCA_LANE_STATUS=2 ;;
        esac
    done
    DCA_RECORD=$dca_lv_record
    return 0
}
