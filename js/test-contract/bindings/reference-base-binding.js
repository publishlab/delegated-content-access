// @ts-check

// The reference implementation's explicit base-contract selection. Each role
// keeps its target-owned driver; this module only declares their composition.

import { dcaTestBinding as endpoint } from "../issuer-endpoint/bindings/reference-issuer-endpoint-binding.js";
import { dcaTestBinding as core } from "../issuer-core/bindings/reference-issuer-core-binding.js";

export const dcaTestBinding = Object.freeze({
  targets: Object.freeze({
    ...endpoint.targets,
    ...core.targets,
  }),
});
