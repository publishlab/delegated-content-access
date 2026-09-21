// @ts-check
// Variant comparison: accessGroup-only catches a cross-accessGroup move but not the other
// four relabel dimensions. The shared cases are also the shipped invariant;
// this entry supplies only the implementation, its display name, and the
// exact failures expected from this rejected construction.

/*
  Attack vector 1: Reuse a contentKey grant across article renders (for example, a single-article purchase)

    - The issuer grants the client Article A's contentKey for one item in one render.
    - The issuer remembers that grant so the client can unlock A again after it is rendered with a new contentKey.
    - On a later unlock for A, the client replaces A's sealed contentKey blob with the blob from Article B.
    - The policy still grants A. If both blobs have the same bound accessGroup, this variant cannot distinguish them and opens B's blob.
    - The client receives B's contentKey and uses it with B's ciphertext.


  Attack vector 2: Turn a contentKey grant into a periodKey capability

    - The issuer grants the client Article A's bodytext contentKey.
    - The client replaces A's sealed contentKey blob with an issuer-sealed premium periodKey blob from a page.
    - This variant binds both blobs only to premium; it does not distinguish contentKey from periodKey.
    - The issuer returns the periodKey under A's contentKey grant.
    - The client uses that periodKey to unlock premium content from other articles in that period.


  Attack vector 3: Use a periodKey grant for t1 to obtain the periodKey for t2

    - The issuer grants the client period t1 for one accessGroup.
    - The client replaces the sealed periodKey blob for t1 with the blob for t2.
    - This variant binds both blobs only to the accessGroup; it does not distinguish t1 from t2.
    - The issuer returns the periodKey for t2 under the grant for t1.
    - The client uses that periodKey to unlock premium articles in t2.

*/

import {
  sealSection,
  unsealSection,
} from "../../_implementation/bind-on-accessGroup/sealedSection.js";
import { registerBindingRelabelSuite } from "../../../test-lib/suites/binding-relabel.js";

const variant = { seal: sealSection, unseal: unsealSection };

registerBindingRelabelSuite({
  binding: variant,
  bindingLabel: "accessGroup-only",
  suiteLabel: "Sealed value bound to: accessGroup (rejected: misses relabel coordinates)",
  // The exact failures are pinned here. Each runs the unchanged shipped
  // refusal assertion as a TODO, so the run prints the unsafe outcome
  // without making the optional experiments directory fail the reference test tier.
  expectedFailures: [
    "same-render-different-contentName",
    "cross-render",
    "key-kind",
    "cross-period",
  ],
});
