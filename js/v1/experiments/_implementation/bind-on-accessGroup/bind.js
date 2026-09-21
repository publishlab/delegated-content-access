// @ts-check
// Sibling to base source: js/v1/core-shared--publisher-issuer/bind.js
//
// The scope-only binding commits a seal to the access tier and to nothing
// else. This variant is useful for comparing a weaker binding with the core
// coordinate binding.
//
// The seal reproduces one value, the tier name, on both kinds of sealed blob.
// The two key kinds use the same access-tier value:
//
//     wrappedContentKey = wrap(contentKey, issuerPubKey, algorithm, encodeUtf8(scope))
//     wrappedWrapKey    = wrap(wrapKey,    issuerPubKey, algorithm, encodeUtf8(scope))
//
// The issuer rebuilds that value from the access decision when opening.
//
// The local vocabulary is accessGroup, periodKey, and t throughout.
//
// No separate proof is needed for this variant. The issuer walks the sealed
// maps, rebuilds the accessGroup value, and returns the keys it opens.
//
// This binding stops a cross-accessGroup substitution: it changes the
// authenticated label and fails the carrier check.
//
// This binding leaves open everything the value does not name. No renderId, so a
// blob is not stuck to one render; no resourceId, so it is not stuck to one
// article; no contentName, so two items sharing a tier are interchangeable;
// and no kind, so a contentKey blob and a periodKey blob are bound by the same
// string.
//
// `t` is also absent. A cross-`t` move opens and returns the periodKey from the
// other bucket under the requested label. That exact key still unwraps content
// from its real period; core instead binds `t` and refuses the move.
//
// This variant deliberately moves only the bound value. The content layer,
// carriers, and wire shape remain those of the core format.
//
// A result here is about the binding value and nothing else.

import { dcaError } from "../../../core-shared/errors.js";

/**
 * The whole of what a seal commits to under this shape: the access tier the
 * blob was sealed for, and no second field.
 *
 * There is no version prefix, no kind char and no delimiter, because there is
 * one field and nothing to separate it from. That is the shape being
 * reproduced rather than an omission to fix. A value with more in it is the
 * `bind-on-renderId-and-slot` experiment.
 *
 * @typedef {object} Binding
 * @property {string} accessGroup
 */

/**
 * @param {Binding} binding
 * @returns {string}
 */
export function bindValue(binding) {
  if (binding === null || typeof binding !== "object") {
    throw dcaError("binding_failed", "a binding is an object naming the access tier");
  }

  const { accessGroup } = binding;
  if (typeof accessGroup !== "string" || accessGroup.length === 0) {
    throw dcaError(
      "binding_failed",
      "the bound value is the accessGroup, and this binding names none",
    );
  }

  return accessGroup;
}
