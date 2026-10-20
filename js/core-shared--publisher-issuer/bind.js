// @ts-check
//
// The publisher seals each key blob under this value, so the blob opens only at
// the coordinate it was sealed at. Normative grammar: docs/spec--sealed-key-envelopes.md
// Section 3. This implementation and its binding tests provide reference evidence.
//
// The value has one of three grammars, depending on the key kind:
//
//     content:  dca-bind-key-envelope | c | renderId | contentName
//     period:   dca-bind-key-envelope | p | renderId | accessGroup | t
//     chain:    dca-bind-key-envelope | pc | renderId | accessGroup | suppliedT
//               | chainsPerDay | periodMinutes
//
// `dca-bind-key-envelope` domain-separates the value. The kind field keeps all three forms
// apart if the field set changes. With the current fields, a content value has
// four fields, a period-key value has five and a chain value has seven. The delimiter is banned
// inside every field, so today the arity separates them; the char separates them
// once that stops being true. `renderId` scopes the value to the render the
// publisher signed. The access key (`contentName` for a contentKey,
// `accessGroup` for a periodKey) binds the blob against relabelling. `t` pins a
// periodKey blob to its bucket. An issuer returns at that granularity: granting
// reads names alone, and a caller gets a chosen-length prefix of the periods a
// render ships.
// `suppliedT` holds the chain position in the same field slot. The period-key
// label and the sealed chain-key position are different coordinates, so they
// get different field names, and each binding names exactly one of them.
//
// The encoding depends entirely on the delimiter. The grammar puts `|` between
// fields and bans it inside every field; `core-shared/names` enforces that ban
// for the identifiers that enter a binding.
// Each delimiter fixes a field boundary, so a binding identifies its fields
// without relying on their widths or parsing a period label as a date.
// There is no length-prefix codec to disagree about across runtimes, because
// no bound field can carry an arbitrary byte.
//
// A bound renderId is exactly 16 random bytes, carried as 22 canonical unpadded
// base64url characters. One width avoids separate floor and
// ceiling rules across runtimes. It is refused at seal and at unseal when it
// does not have that shape.
// No code can check the other half, freshness per render, because the issuer
// has never seen the render before.
//
// `renderId` is bound as the base64url string it appears as on the wire, so
// there is one encoding of it in the system and nothing has to agree on decoded
// bytes.

import { binaryStringBytes } from "../core-shared/binaryStrings.js";
import { dcaError } from "../core-shared/errors.js";
import { validateAccessGroup, validateContentName } from "../core-shared/names.js";
import { inspectPeriodGeometryBounds } from "../core-shared/geometryBounds.js";
import { isPeriodKeyLabel } from "../core-shared/periodLabels.js";

/** Domain separation and identity of this fixed grammar. */
export const BIND_IDENTIFIER = "dca-bind-key-envelope";

/** The field boundary, banned inside every field it separates. */
export const BIND_DELIMITER = "|";

/** contentKey blobs. */
export const CONTENT_KIND = "c";

/** periodKey blobs. */
export const PERIOD_KIND = "p";

/** chainKey blobs. */
export const CHAIN_KEY_BIND_KIND = "pc";

/** The exact width of a bound renderId before base64url encoding. */
export const RENDER_ID_BYTES = 16;

/**
 * A coordinate one sealed blob is bound at. `contentName` names a contentKey
 * blob; `accessGroup` with `t` names a periodKey blob, and `accessGroup`
 * with `suppliedT` and complete geometry names a chainKey blob. One of the
 * three, never two. A value that could be read as either does not name what it
 * binds.
 *
 * @typedef {object} Binding
 * @property {string} renderId - as the wire carries it, base64url
 * @property {string} [contentName]
 * @property {string} [accessGroup]
 * @property {string} [t] - the period-key label, on a `p` binding
 * @property {string} [suppliedT] - the sealed chain-key position, on a `pc`
 *   binding. It carries the same bytes as a `t`, under the name the chain
 *   coordinate grammar gives it.
 * @property {boolean} [chainKey]
 * @property {number} [chainsPerDay]
 * @property {number} [periodMinutes]
 */

/**
 * @param {unknown} value
 * @param {string} field - for the message
 * @returns {string}
 */
function bindable(value, field) {
  // docs/spec--sealed-key-envelopes.md §3.2
  if (typeof value !== "string" || value.length === 0) {
    throw dcaError("binding_failed", `${field} is not a string a binding can carry`);
  }
  if (value.includes(BIND_DELIMITER)) {
    throw dcaError(
      "binding_failed",
      `${field} ${JSON.stringify(value)} carries the delimiter, which would make it two fields`,
    );
  }
  return value;
}

/**
 * Bind has its own failure boundary, while the identifier and chain grammars are
 * each implemented once, elsewhere. Do not recreate either grammar beside the
 * bytes this function joins.
 *
 * @param {() => string} validate
 * @param {string} field
 */
function bindingField(validate, field) {
  try {
    return validate();
  } catch {
    throw dcaError("binding_failed", `${field} is not valid for this binding`);
  }
}

/**
 * @param {unknown} suppliedT
 * @param {unknown} chainsPerDay
 * @param {unknown} periodMinutes
 * @returns {{ suppliedT: string, chainsPerDay: string, periodMinutes: string }}
 */
function chainBindingFields(suppliedT, chainsPerDay, periodMinutes) {
  const geometry = inspectPeriodGeometryBounds(chainsPerDay, periodMinutes);
  if (geometry.kind !== "valid") {
    const field = geometry.kind === "invalidChainsPerDay" ? "chainsPerDay" : "periodMinutes";
    throw dcaError("binding_failed", `${field} is a positive integer in a chain-key binding`);
  }
  try {
    if (
      typeof suppliedT !== "string" ||
      typeof periodMinutes !== "number" ||
      suppliedT.length !== 11 ||
      !isPeriodKeyLabel(suppliedT)
    )
      throw new Error();
    const year = 2000 + Number(suppliedT.slice(0, 2));
    const month = Number(suppliedT.slice(2, 4));
    const day = Number(suppliedT.slice(4, 6));
    const hour = Number(suppliedT.slice(7, 9));
    const minute = Number(suppliedT.slice(9, 11));
    const at = new Date(Date.UTC(year, month - 1, day, hour, minute));
    if (
      at.getUTCFullYear() !== year ||
      at.getUTCMonth() !== month - 1 ||
      at.getUTCDate() !== day ||
      at.getUTCHours() !== hour ||
      at.getUTCMinutes() !== minute ||
      (hour * 60 + minute) % periodMinutes !== 0
    )
      throw new Error();
    return {
      suppliedT,
      chainsPerDay: String(chainsPerDay),
      periodMinutes: String(periodMinutes),
    };
  } catch {
    throw dcaError(
      "binding_failed",
      "a chain-key binding names a valid suppliedT and complete geometry",
    );
  }
}

/**
 * The renderId every blob of one render is bound under, checked for the entropy
 * the binding rests on. The value is bound as the string, so this function
 * decodes it only to check it and never joins the decoded bytes.
 *
 * It is exported because a caller can check it once per request: an issuer
 * takes it from the verified resourceJWT before it opens anything, and if a
 * render's renderId fails, no coordinate in that render can pass.
 *
 * @param {unknown} renderId
 * @returns {string}
 */
export function validateRenderId(renderId) {
  // docs/spec--sealed-key-envelopes.md §3.2
  const value = bindable(renderId, "renderId");

  const bytes = binaryStringBytes(value);
  if (bytes === null) {
    throw dcaError(
      "binding_failed",
      "renderId is canonical base64url on the wire and this one is not",
    );
  }
  if (bytes.length !== RENDER_ID_BYTES) {
    throw dcaError(
      "binding_failed",
      `renderId must be exactly ${RENDER_ID_BYTES} bytes in canonical unpadded base64url`,
    );
  }

  return value;
}

/**
 * Returns the fields of one binding in the order the grammar joins them, with
 * the kind char already chosen. It is split out from bindValue because a caller
 * demonstrating another encoding has to join the same fields another way.
 *
 * @param {Binding} binding
 * @returns {string[]}
 */
export function bindFields(binding) {
  // docs/spec--sealed-key-envelopes.md §3.1; §3.2
  if (binding === null || typeof binding !== "object") {
    throw dcaError("binding_failed", "a binding is an object naming one coordinate");
  }

  const {
    renderId,
    contentName,
    accessGroup,
    t,
    suppliedT,
    chainKey,
    chainsPerDay,
    periodMinutes,
  } = binding;
  const content = contentName !== undefined;
  const period = accessGroup !== undefined || t !== undefined || suppliedT !== undefined;
  const geometry = chainsPerDay !== undefined || periodMinutes !== undefined;

  if (content && period) {
    throw dcaError(
      "binding_failed",
      "a binding names a contentName or an accessGroup with its period label, never both",
    );
  }
  if (content) {
    if (chainKey !== undefined || geometry) {
      throw dcaError("binding_failed", "a contentKey binding cannot name a chain-key kind");
    }
    return [
      BIND_IDENTIFIER,
      CONTENT_KIND,
      validateRenderId(renderId),
      bindingField(() => validateContentName(contentName), "contentName"),
    ];
  }

  // This code reads the kind from the boolean, never from which label is
  // present. It refuses a non-boolean value here instead of downgrading a chain
  // coordinate to a period-key one.
  if (chainKey !== undefined && typeof chainKey !== "boolean") {
    throw dcaError("binding_failed", "chainKey is a boolean when a period binding names it");
  }
  const chain = chainKey === true;
  const labelField = chain ? "suppliedT" : "t";
  const label = chain ? suppliedT : t;

  // Each kind takes one label. The two labels carry the same bytes but mean
  // different coordinates, so a binding that names the other kind's field does
  // not say which coordinate its blob is bound at.
  if (chain && t !== undefined) {
    throw dcaError(
      "binding_failed",
      "a chain-key binding names its position as suppliedT, and t is the period-key label",
    );
  }
  if (!chain && suppliedT !== undefined) {
    throw dcaError(
      "binding_failed",
      "suppliedT is the chain-key position, and a period-key binding names its t",
    );
  }

  if (accessGroup !== undefined && label !== undefined) {
    const fields = [
      BIND_IDENTIFIER,
      chain ? CHAIN_KEY_BIND_KIND : PERIOD_KIND,
      validateRenderId(renderId),
      bindingField(() => validateAccessGroup(accessGroup), "accessGroup"),
      bindable(label, labelField),
    ];
    if (chain) {
      if (!geometry) {
        throw dcaError(
          "binding_failed",
          "a chain-key binding names its complete geometry, so a chain key relabeled into another " +
            "geometry fails the tag rather than deriving under it",
        );
      }
      const chainFields = chainBindingFields(suppliedT, chainsPerDay, periodMinutes);
      fields[4] = chainFields.suppliedT;
      fields.push(chainFields.chainsPerDay, chainFields.periodMinutes);
    } else if (geometry) {
      throw dcaError("binding_failed", "chain geometry belongs only to a chain-key binding");
    }
    return fields;
  }
  if (period) {
    throw dcaError(
      "binding_failed",
      `a periodKey coordinate is an accessGroup and a ${labelField}, and this names one`,
    );
  }
  if (chainKey !== undefined || geometry) {
    throw dcaError(
      "binding_failed",
      "a chain-key binding also names an accessGroup and a suppliedT",
    );
  }
  throw dcaError(
    "binding_failed",
    "a binding names the coordinate its blob sits at, and this names none",
  );
}

/**
 * Returns the binding value. It is passed as AES-GCM `additionalData` on the
 * ECDH carrier and as the OAEP plaintext prefix on the RSA carrier. It is the
 * same string on both carriers, so an issuer holding both key types can build
 * it once.
 *
 * @param {Binding} binding
 * @returns {string}
 */
export function bindValue(binding) {
  return bindFields(binding).join(BIND_DELIMITER);
}
