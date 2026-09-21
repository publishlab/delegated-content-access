// @ts-check
//
// This extension as a `contentKeySource` for the base issuer engine: another
// way to produce one already-granted content key, and nothing beside it.
//
// Base owns the unlock. It verifies, decides once, clamps the decision to the
// coordinates the request presented, refuses a complete denial before any
// opening key is looked up, resolves the registration-scoped key state, opens
// the granted direct and exact-period values and files what came back. This
// module adds the second try for one content name: the candidates the
// client forwarded, unwrapped under period material this issuer was already
// entrusted with.
//
// The contentName is the policy's, out of what the request presented, and so
// is the `(accessGroup, t)` it may be opened through: the policy answers
// `sourceGrants`, clamped to the labels the request carried the way a period
// prefix is clamped. The accessGroup and t beside a candidate are labels that
// select which sealed period blob is opened under the outer BIND, and nothing
// more. The inner binding is rebuilt from base's verified renderId, the
// policy's contentName and that same pair, so a candidate carried to another
// render, name, group or period fails authentication and yields no key.
//
// The issuer host selects this source's exact leaf view from the authenticated
// publisher registration after authorization and active opening-key resolution.
// Only that opaque selected view travels here, and it takes `(accessGroup, t)`
// with no publisher selector to get wrong. A registration with no view held is
// a miss that reaches nothing: there is no global source under the selection to
// fall back to.
//
// That is the whole of the isolation argument. `(accessGroup, t)` is a
// coordinate inside one publisher's render rather than a global one, and both
// renderIds and both bound candidates travel in public pages, so a registered
// publisher can present another publisher's candidate under its own valid
// token. It cannot reach the other publisher's leaf view, because selecting
// one needs the registration object in the host and never anything a request
// can spell.
//
// A retired keyId never reaches here: base asks no content-key source once the
// opening key is let go, so material this module could produce on its own
// cannot answer under a key the issuer no longer holds.
//
// Every candidate is tried. A coordinate that will not open lets the next
// candidate try, and the item reports one failure only when every eligible
// candidate is spent. Base holds that failure beside the direct seal's own and
// files one of them, or neither when something answered.

import { candidatesFor, presentedCoordinates } from "./omissionCandidates.js";

/** What an item no candidate opened reports, in base's own wording. */
const UNSEAL_FAILED = Object.freeze({
  error: "unseal_failed",
  message: "sealed value could not be opened",
});

/** @returns {import('../../../core-issuer/IssuerEngine.js').ContentKeySource} */
export function omissionContentKeySource() {
  return {
    /**
     * The coordinates this request presents that the ordinary reading does
     * not see: the content names the forwarded candidates carry, and the
     * period families their labels name. A group presented only by a
     * candidate still opens no period key - the ordinary period route reads
     * the sealed period map alone - but a policy that cannot see the group
     * cannot decide among them.
     *
     * @param {any} request
     */
    presented(request) {
      return presentedCoordinates(request);
    },

    /**
     * What this source can produce for this unlock, by granted content name.
     *
     * @param {import('../../../core-issuer/IssuerEngine.js').ContentKeyUnlock} unlock
     */
    contentKeys({ request, decision, scope, renderId, open }) {
      // The host chose one exact leaf view for this authenticated unlock.
      // A missing or malformed view is an ordinary source miss; this
      // source has neither a registration nor any global fallback to use.
      const leafFor = typeof scope === "function" ? scope : null;
      const byContentName = candidatesFor({ request, decision, leafFor });

      // One coordinate, one ask, however many items reach for it: neither
      // this issuer's leaf for a coordinate nor the value presented at one
      // changes inside a single unlock.
      /** @type {Map<string, Promise<Uint8Array|null>>} */
      const material = new Map();
      /** @param {import('./omissionCandidates.js').OmissionCandidate} candidate */
      const materialFor = (candidate) => {
        const { accessGroup, t } = candidate.coordinate;
        const at = `${candidate.leaf !== undefined ? "leaf" : "sealed"} ${accessGroup}|${t}`;
        let pending = material.get(at);
        if (pending === undefined) {
          pending =
            candidate.leaf !== undefined
              ? Promise.resolve(candidate.leaf()).then((held) =>
                  held instanceof Uint8Array ? held : null,
                )
              : open(candidate.sealed, candidate.coordinate).then((opened) =>
                  "error" in opened ? null : opened.bytes,
                );
          material.set(at, pending);
        }
        return pending;
      };

      /**
       * @param {string} contentName
       * @returns {Promise<import('../../../core-issuer/IssuerEngine.js').ContentKeyAnswer>}
       */
      return async (contentName) => {
        const forwarded = byContentName.get(contentName);
        if (forwarded === undefined) return { miss: true };

        for (const candidate of forwarded) {
          const periodKey = await materialFor(candidate);
          if (periodKey === null) continue;
          try {
            const bytes = await candidate.unwrap(periodKey, renderId);
            if (bytes instanceof Uint8Array) return { bytes };
          } catch (cause) {
            // A candidate that will not unwrap was not the one; the
            // next one is still allowed to answer this item.
          }
        }

        // Candidates reached this item and none of them opened it. That
        // is this item's own failure, and base files it only where
        // nothing else answered.
        return { error: UNSEAL_FAILED };
      };
    },
  };
}
