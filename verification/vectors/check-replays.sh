#!/bin/sh
# Explicit all-set maintainer gate. This is not a role or profile claim.
# Each replayer checks exact membership inside the set it owns.

set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
js_dir=$here/../../js
map_only=no

if [ "${1:-}" = --check-map ]; then
    map_only=yes
    shift
    [ "$#" -gt 0 ] || { echo "check-replays: --check-map needs set names" >&2; exit 2; }
    sets=$*
else
    [ "$#" -eq 0 ] || { echo "check-replays: no set selector; this gate walks all sets" >&2; exit 2; }
    # shellcheck source=read-sets.sh
    . "$here/read-sets.sh"
    read_set_manifest "$here/sets.txt" "$here" || exit 2
    sets=$DCA_VECTOR_SETS
fi

base=no
ecdh=no
client_bound=no
bind=no
chain_keys=no
for set_name in $sets; do
    case $set_name in
        v1/baseline/rsa-oaep-envelope-open) base=yes ;;
        v1/baseline/ecdh-p256-envelope-open) ecdh=yes ;;
        v1/profiles/dca-profile-client-bound-ecdh-p256|v1/profiles/dca-profile-client-bound-rsa-oaep)
            client_bound=yes ;;
        v1/profiles/dca-profile-chain-keys) chain_keys=yes ;;
        v1/experiments/bind-on-renderId-and-slot) bind=yes ;;
        *) echo "check-replays: no replayer for set $set_name" >&2; exit 2 ;;
    esac
done

[ "$map_only" = yes ] && exit 0

# Reject absent replayers before producing any partial success report.
[ "$base" = no ] || [ -f "$js_dir/test-vectors/vectors.test.js" ] || exit 2
[ "$ecdh" = no ] || [ -f "$js_dir/test-vectors/ecdh-open.test.js" ] || exit 2
[ "$client_bound" = no ] || [ -f "$js_dir/test-vectors/client-bound-vectors.test.js" ] || exit 2
[ "$bind" = no ] || [ -f "$js_dir/test-vectors/bind.test.js" ] || exit 2
[ "$chain_keys" = no ] || [ -f "$here/check-chain-key-primitives.py" ] || exit 2

sh "$here/check-sums.sh" || exit $?

if [ "$base" = yes ]; then
    (cd "$js_dir" && node --test --test-reporter=dot test-vectors/vectors.test.js) || exit $?
fi
if [ "$ecdh" = yes ]; then
    (cd "$js_dir" && node --test --test-reporter=dot test-vectors/ecdh-open.test.js) || exit $?
fi
if [ "$client_bound" = yes ]; then
    (cd "$js_dir" && node --test --test-reporter=dot test-vectors/client-bound-vectors.test.js) || exit $?
fi
if [ "$bind" = yes ]; then
    (cd "$js_dir" && node --test --test-reporter=dot test-vectors/bind.test.js) || exit $?
fi
if [ "$chain_keys" = yes ]; then
    python3 "$here/check-chain-key-primitives.py" || exit $?
fi

echo "RESULT: every manifest set was replayed at its declared boundary."
