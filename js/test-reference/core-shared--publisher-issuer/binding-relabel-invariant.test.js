// @ts-check
// Construction evidence for the shipped dca-bind-key-envelope binding:
// five relabels, two carriers, ten strict refusals through a modeled section walk.
// Real issuer per-coordinate refusal is covered in ../core-issuer/jwt-proof.test.js.

import { sealSection, unsealSection } from "../../test-lib/harnesses/sealedSection.js";
import { registerBindingRelabelSuite } from "../../test-lib/suites/binding-relabel.js";

const shipped = { seal: sealSection, unseal: unsealSection };

registerBindingRelabelSuite({
  binding: shipped,
  bindingLabel: "dca-bind-key-envelope",
  suiteLabel:
    'Sealed value bound to: "dca-bind-key-envelope" | contentKey / periodKey | renderId | contentName / accessGroup+time',
});
