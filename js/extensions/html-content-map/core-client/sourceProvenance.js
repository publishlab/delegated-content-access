// @ts-check
//
// Server-side source provenance, docs/spec-proposal--html-content-map.md Section 8. A
// server-side client places items on the authority of the page it fetched, so
// before it places anything it establishes that the page came from the
// publisher:
//
// 1. trusted source configuration admits the URL a caller names, and each
//    redirect target (`admitSourceUrl`, here);
// 2. the client fetches over HTTPS itself (`adapter-client/sourceFetch.js`,
//    which calls `admitSourceUrl` for every hop);
// 3. the delivery's `resourceJWT` verifies under a trusted publisher
//    registration key, and the final URL's origin equals the verified `origin`
//    claim (`verifyResourceAssertion`, here).
//
// Each failure is the map failure `source_refused`. The attack this stops: a
// caller submits its own page carrying a genuine token, `dca-data` and
// ciphertext copied from a real article and its own map. Only a page the
// client fetched from an admitted source, signed for the origin that served it,
// reaches placement.
//
// The verification runs on every response, including one whose items all open
// from cached capability without issuer contact; the gateway calls it before
// it asks for any key. This module makes no network call: both functions are
// pure over plain data and injected keys.
//
// `verifyResourceAssertion` copies the ES256 header pin and signature check of
// `core-shared--publisher-issuer/jwt.js` (`requireFixedHeader`, `verify`). A
// client-role slice may not import that module, and base has no client-side
// verification seam, because a base client never verifies the token; the
// issuer does. Section 8 asks for the core Section 4.2 header, registration and
// signature verification plus the final-origin check, so this module checks no
// other claim. The issuer admits `renderId`, `resourceId` and `issuedAt` with
// its own validators when an unlock request carries the token.

import { base64urlDecode, utf8Encode } from "../../../core-shared/codec.js";
import { decodeCompactJwt } from "../../../core-shared/compactJwt.js";
import { es256Verify } from "../../../core-shared/cryptoProvider.js";
import { DcaError, dcaError } from "../../../core-shared/errors.js";
import { own } from "../../../core-shared/wire.js";

/**
 * One trusted publisher source: the exact origin, and optionally the path
 * prefix under it that the configuration admits.
 *
 * @typedef {object} PublisherSource
 * @property {string} origin - e.g. `https://pub.example`
 * @property {string} [pathPrefix] - e.g. `/articles/`; left out, every path
 */

/**
 * One trusted publisher registration: an identity the gateway scopes cached
 * capability under, and the verification keys by `kid`.
 *
 * @typedef {object} PublisherRegistration
 * @property {string} id
 * @property {Record<string, CryptoKey>} keys - ES256 public keys by `kid`
 */

/**
 * The `source_refused` error, thrown at the call site so type narrowing sees
 * the throw. The fetch adapter throws it too.
 *
 * @param {string} why
 */
export function sourceRefused(why) {
  return dcaError("source_refused", why);
}

/**
 * The URL to fetch when the configuration admits it, or null. The URL is an
 * absolute `https` URL without credentials; a fragment never reaches the
 * server, so it is dropped rather than refused.
 *
 * @param {unknown} url
 * @param {readonly PublisherSource[]} sources
 * @returns {string|null}
 */
export function admitSourceUrl(url, sources) {
  if (typeof url !== "string") return null;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "") {
    return null;
  }
  parsed.hash = "";
  const admitted = sources.some(
    (source) =>
      source.origin === parsed.origin &&
      (source.pathPrefix === undefined || parsed.pathname.startsWith(source.pathPrefix)),
  );
  return admitted ? parsed.href : null;
}

/**
 * The URL a redirect's `Location` names, resolved against the URL that
 * answered, when the configuration admits it; otherwise null.
 *
 * @param {string|null} location - the `Location` header, or null when absent
 * @param {string} from - the admitted URL that answered with the redirect
 * @param {readonly PublisherSource[]} sources
 * @returns {string|null}
 */
export function admitRedirectTarget(location, from, sources) {
  if (location === null) return null;
  let next;
  try {
    next = new URL(location, from).href;
  } catch {
    return null;
  }
  return admitSourceUrl(next, sources);
}

/**
 * The origin of an admitted URL, the value `verifyResourceAssertion` compares
 * with the verified `origin` claim.
 *
 * @param {string} url
 * @returns {string}
 */
export function sourceOrigin(url) {
  return new URL(url).origin;
}

/**
 * Verify the delivery's `resourceJWT` under the trusted registrations, as core
 * Section 4.2 defines verification, and require the final URL's origin to
 * equal the verified `origin` claim.
 *
 * The header pins `alg` ES256 and `typ` JWT before any key lookup; the `kid`
 * resolves exactly one key across every registration, and a `kid` two
 * registrations hold is refused as ambiguous.
 *
 * @param {object} assertion
 * @param {unknown} assertion.token - the delivery's `resourceJWT`
 * @param {readonly PublisherRegistration[]} assertion.registrations
 * @param {string} assertion.finalOrigin - the origin of the fetched final URL
 * @returns {Promise<{ registration: string, claims: any }>}
 */
export async function verifyResourceAssertion({ token, registrations, finalOrigin }) {
  let decoded;
  try {
    decoded = decodeCompactJwt(token);
  } catch (cause) {
    if (!(cause instanceof DcaError)) throw cause;
    throw sourceRefused("the delivery carries no compact resourceJWT");
  }
  const {
    header,
    payload,
    parts: [head, body, signature],
  } = decoded;
  if (own(header, "alg") !== "ES256" || own(header, "typ") !== "JWT") {
    throw sourceRefused("the resourceJWT header is not ES256 JWT");
  }
  const kid = own(header, "kid");
  if (typeof kid !== "string" || kid.length === 0)
    throw sourceRefused("the resourceJWT names no kid");
  const holders = registrations.filter((registration) => Object.hasOwn(registration.keys, kid));
  if (holders.length !== 1) {
    throw sourceRefused(
      `the kid resolves ${holders.length} trusted registrations, not exactly one`,
    );
  }
  const [registration] = holders;

  let verified;
  try {
    verified = await es256Verify(
      registration.keys[kid],
      base64urlDecode(signature),
      utf8Encode(`${head}.${body}`),
    );
  } catch {
    verified = false;
  }
  if (!verified) throw sourceRefused("the resourceJWT does not verify under its registration key");

  // The final origin is a canonical serialization from the URL parser, so
  // exact equality also refuses a missing or non-canonical claim.
  if (own(payload, "origin") !== finalOrigin) {
    throw sourceRefused("the final URL's origin differs from the verified origin claim");
  }
  return { registration: registration.id, claims: payload };
}
