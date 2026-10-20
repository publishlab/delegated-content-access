// @ts-check
//
// The `envelope` selector of docs/spec-profile--compact-ecdh.md Section 3.1.
// A publisher writes it into an issuer block, the client copies it unchanged
// into the unlock request, and the issuer reads it there. Every role reads it
// through `readEnvelopeSelector`, so all three agree on what a present value
// means.
//
// An omitted member selects the key's ordinary procedure, when the issuer's
// configuration permits it. The spec defines one present value,
// "compact-ecdh". A present `null`, empty string, non-string or other string is
// refused, never read as omission: a reader that treated it as absent would let
// an edited selector fall back to the ordinary procedure.
//
// The selector itself authorizes nothing. The issuer still checks that its
// trusted configuration permits the selected procedure for the key.

/** The member name in an issuer block and in an unlock request. */
export const ENVELOPE_MEMBER = "envelope";

/** The one value this profile defines. */
export const COMPACT_ECDH = "compact-ecdh";

/**
 * @typedef {"omitted"|"compact"|"refuse"} EnvelopeSelection
 */

/**
 * Reads the own `envelope` member of an issuer block or unlock request.
 * A value that is not a plain record reads as `refuse`, because nothing in it
 * can be trusted to say "omitted".
 *
 * @param {unknown} carrier - the issuer block or the unlock request
 * @returns {EnvelopeSelection}
 */
export function readEnvelopeSelector(carrier) {
  if (carrier === null || typeof carrier !== "object" || Array.isArray(carrier)) return "refuse";
  const record = /** @type {Record<string, unknown>} */ (carrier);
  if (!Object.hasOwn(record, ENVELOPE_MEMBER)) return "omitted";
  return record[ENVELOPE_MEMBER] === COMPACT_ECDH ? "compact" : "refuse";
}
