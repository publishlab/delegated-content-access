# The whole of what a lane check runs, with the record that follows it. Sourced
# beside cache.sh, after DCA_LANE is set:
#
#     . "$HERE/../_shared/driver-steps.sh"
#     run_driver_steps
#     if [ -n "${DCA_RECORD:-}" ]; then
#         write_driver_record || DCA_WALK_STATUS=2
#     fi
#     exit "$DCA_WALK_STATUS"
#
# A lane check runs one step: the case corpus through this lane's own operation
# bridge, one set at a time. The corpus groups its cases into sets by the
# operations they ask for, so a lane that answers four of the seven operations
# still holds the sets it can answer, and the run names the sets nobody asked
# it.
#
# The steps take no argument. A lane check resolves a toolchain of its own only
# to print a version banner; the steps run through that lane's bridge.json,
# which owns a separate toolchain install, so nothing a check resolves for
# itself narrows what they answer.
#
# `_shared/driver/select-sets.mjs` names the corpus sets and says which of them
# this lane declares every operation for. `_shared/driver/run.mjs --set` then
# answers one set, as a child process whose exit code is read back: the same
# 0/1/2 `RUN_EXIT` names run.mjs exits with. Nothing here reads an expected
# value, decides a case or writes a parser.
#
# This file finds the driver from its own location (DCA_DRIVER_STEPS_HERE,
# below): a file under _shared/ reaches its own sibling directly rather than
# going out through the caller's HERE and back in again. DCA_LANE is the only
# thing this file reads from its caller.
DCA_DRIVER_STEPS_HERE="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
# DCA_SETS_STATUS and appends one row per set to DCA_DRIVER_ROWS:
# `set=<name> status=held|disagreed|incomplete|unsupported`.
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

    while IFS= read -r dca_ds_line; do
        [ -n "$dca_ds_line" ] || continue
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
        DCA_DRIVER_ROWS="${DCA_DRIVER_ROWS:-}set=$dca_ds_name status=$dca_ds_word
"
    done < "$dca_ds_selection"
    rm -f "$dca_ds_selection"

    # A selection that named no set at all leaves a lane claiming a hold over
    # nothing, so it is incomplete instead.
    if [ -z "${DCA_DRIVER_ROWS:-}" ]; then
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

# The record a run writes: lane=, then DCA_DRIVER_ROWS (the set= rows the step
# above appended, in corpus order), then the exit line, written from the same
# DCA_WALK_STATUS the caller is about to exit with, so the record and the exit
# status always match.
#
#     lane=php
#     set=encoding status=held
#     set=aes-gcm-128 status=held
#     set=hkdf status=unsupported
#     exit=0
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
    if { printf 'lane=%s\n' "$DCA_LANE"
         printf '%s' "${DCA_DRIVER_ROWS:-}"
         printf 'exit=%s\n' "$DCA_WALK_STATUS"
       } > "$DCA_RECORD.tmp" && mv "$DCA_RECORD.tmp" "$DCA_RECORD"; then
        return 0
    fi
    echo "the run was asked to record its result to $DCA_RECORD and could not write it." >&2
    echo "A run that cannot leave the record it was asked for verified less than it was asked to." >&2
    return 1
}
