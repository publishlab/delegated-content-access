// @ts-check
//
// The key-kind context both client-bound methods bind into every wrapped key
// (docs/spec--response-binding.md section 6). The result section fixes the
// kind: `keys.contentKeys` holds `contentKey` entries, `keys.periodKeys` holds
// `periodKey` entries and `keys.chainKeys` holds `chainKey` entries. The issuer
// names the section it writes, and the client names the admitted section it
// reads. ECDH-P256 passes the context as AES-GCM additional data and RSA-OAEP
// passes it as the OAEP label, so a key entry moved into another section fails its
// tag or padding check. Neither side reads the kind off the key width, the
// requested usages or the ciphertext, and neither side has a default: a
// missing kind is a caller error, never an empty context.
//
// A selected extension may compose further kinds for its own response
// sections. Trusted composition settles them once with `settleKindDescriptors`
// and hands the frozen set to the capability and the sealer; each kind states
// its width and whether it opens to raw bytes or to an AES handle. The same
// context construction binds them. The wire never names or defines a kind.

import { utf8Encode } from "../../../core-shared/codec.js";
import { dcaError } from "../../../core-shared/errors.js";

/** @typedef {'contentKey'|'periodKey'|'chainKey'} KeyKind */

/** The fixed label in front of the kind; the zero octet after it ends the label. */
const KIND_CONTEXT_LABEL = "dca-bind-client-bound-key-kind";

/**
 * How a client opens one key kind: `width` octets, either as raw bytes for a
 * derivation (`raw`) or as a non-extractable AES-GCM handle (`aesHandle`).
 * @typedef {{ width: number, open: 'raw'|'aesHandle' }} KindDescriptor
 */

/** The three base kinds and how they open: chain keys are derivation bytes. */
const BASE_KINDS = Object.freeze({
  contentKey: Object.freeze({ width: 16, open: "aesHandle" }),
  periodKey: Object.freeze({ width: 16, open: "aesHandle" }),
  chainKey: Object.freeze({ width: 16, open: "raw" }),
});

/** The one DCA capability width either method carries. */
const DESCRIPTOR_WIDTHS = Object.freeze([16]);
/** Kind names are protocol identifiers: ASCII, a leading letter, no separators. */
const KIND_NAME = /^[a-z][A-Za-z0-9]{0,63}$/;

/**
 * Descriptor sets that trusted composition settled. A transport accepts a
 * composed kind only through one of these, never through a plain object a
 * caller or the wire could have built.
 * @type {WeakSet<object>}
 */
const SETTLED = new WeakSet();

/**
 * Settle the kinds a selected extension composes beside the base three. Each
 * name is new, each width is 16 octets, and each kind opens `raw` or as an
 * `aesHandle`. The result is frozen and is the only form transport code takes.
 * There is no registry: every capability and sealer holds the set it was given.
 *
 * @param {Record<string, KindDescriptor>} input - kind name to its descriptor
 * @returns {Readonly<Record<string, Readonly<KindDescriptor>>>}
 */
export function settleKindDescriptors(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw dcaError("bad_config", "composed key kinds are a map of kind name to descriptor");
  }
  /** @type {Record<string, Readonly<KindDescriptor>>} */
  const settled = {};
  for (const [kind, descriptor] of Object.entries(input)) {
    if (!KIND_NAME.test(kind) || Object.hasOwn(BASE_KINDS, kind)) {
      throw dcaError(
        "bad_config",
        `a composed key kind needs a new kind name, not ${JSON.stringify(kind)}`,
      );
    }
    const { width, open, ...rest } = /** @type {any} */ (descriptor ?? {});
    if (
      descriptor === null ||
      typeof descriptor !== "object" ||
      Object.keys(rest).length > 0 ||
      !DESCRIPTOR_WIDTHS.includes(width) ||
      (open !== "raw" && open !== "aesHandle")
    ) {
      throw dcaError(
        "bad_config",
        `composed key kind ${kind} is { width: 16, open: 'raw'|'aesHandle' }`,
      );
    }
    settled[kind] = Object.freeze({ width, open });
  }
  const frozen = Object.freeze(settled);
  SETTLED.add(frozen);
  return frozen;
}

/** The empty composed set: base kinds only. */
export const NO_COMPOSED_KINDS = settleKindDescriptors({});

/**
 * How one kind opens: a base kind, or a kind from a settled composed set.
 * A missing, unknown or unsettled kind is `bad_config`; nothing defaults.
 *
 * @param {string} keyKind
 * @param {Readonly<Record<string, Readonly<KindDescriptor>>>} [composed]
 * @returns {Readonly<KindDescriptor>}
 */
export function kindDescriptor(keyKind, composed = NO_COMPOSED_KINDS) {
  if (!SETTLED.has(composed)) {
    throw dcaError("bad_config", "composed key kinds reach a transport only once settled");
  }
  if (typeof keyKind === "string" && Object.hasOwn(BASE_KINDS, keyKind)) {
    return BASE_KINDS[/** @type {KeyKind} */ (keyKind)];
  }
  if (typeof keyKind === "string" && Object.hasOwn(composed, keyKind)) return composed[keyKind];
  throw dcaError(
    "bad_config",
    `a client-bound key entry is bound to contentKey, periodKey, chainKey or a composed kind, not ${JSON.stringify(keyKind)}`,
  );
}

/**
 * The context octets for one key kind: UTF-8 `dca-bind-client-bound-key-kind`, one
 * zero octet, then UTF-8 of the exact kind string. `contentKey` gives the 41
 * octets `dca-bind-client-bound-key-kind\0contentKey`. A composed kind such as
 * `contentGroupPeriodKey` uses the same construction.
 *
 * @param {string} keyKind - the kind of the section being written or read
 * @param {Readonly<Record<string, Readonly<KindDescriptor>>>} [composed] -
 *   the settled composed kinds this transport was given
 * @returns {Uint8Array<ArrayBuffer>}
 */
export function keyKindContext(keyKind, composed = NO_COMPOSED_KINDS) {
  kindDescriptor(keyKind, composed);
  return Uint8Array.from([...utf8Encode(KIND_CONTEXT_LABEL), 0, ...utf8Encode(keyKind)]);
}
