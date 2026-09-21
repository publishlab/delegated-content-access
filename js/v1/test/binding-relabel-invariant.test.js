// @ts-check
// The shipped dca-bind-v1 proof: five relabels, two carriers, ten strict refusals.

import { sealSection, unsealSection } from "../test-lib/harnesses/sealedSection.js";
import { registerBindingRelabelSuite } from "../test-lib/suites/binding-relabel.js";

const shipped = { seal: sealSection, unseal: unsealSection };

registerBindingRelabelSuite({
  binding: shipped,
  bindingLabel: "dca-bind-v1",
  suiteLabel:
    'Sealed value bound to: "dca-bind-v1" | contentKey / periodKey | renderId | contentName / accessGroup+time',
});
