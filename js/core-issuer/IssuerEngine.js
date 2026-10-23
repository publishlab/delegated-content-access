// @ts-check
//
// The port is built on this core. It takes an unlock request, unseals what it was
// sent, and returns keys and per-item errors. It knows nothing about HTTP and
// is callable directly as a library, but only with a request that
// `IssuerProcessor.admit` (in ./IssuerProcessor.js) has already admitted.
//
// This module verifies, decides, then unseals and answers, for both key kinds.
// It supports direct transport only: each key goes back as raw bytes in
// base64url. Client-bound transport is a separate concern, and a scaffold for it
// here would look like a working implementation.
//
// One unlock runs seven steps, in this order and for these reasons. Verify the
// request and the publisher registration it names. Collect the coordinates the
// request presents. Ask the access policy once and clamp its answer to those
// coordinates. Refuse the whole request when nothing at all was granted, which
// happens before any opening key is looked up. Resolve the registration-scoped
// opening-key state once. Open the granted content-key and period-key values.
// Assemble keys, per-item errors, the not-delivered family report and
// `policyData`.
//
// Nothing is opened before the request has been verified whole. The engine
// checks version, publisher registration by kid, the signature over the
// resource and the renderId under it, and looks up the registration's scoped
// opening-key view only after that. An integrity failure throws and the port
// answers 400 for the whole request: the signed resource is where the access
// decision's claims come from and where every blob's binding is anchored, so a
// request that fails there has asked nothing that could be answered in part.
//
// The engine opens each blob at one coordinate. The publisher sealed the blob
// bound to that coordinate, and this engine rebuilds that commitment from the
// verified renderId and the request member name it is walking. The access
// decision was made on that same string. Soundness depends on this: each blob
// has one label, and an attacker has no second label beside it to move
// independently.
// A blob presented at a coordinate it was not sealed at fails to open, which is
// a per-item error beside a 200, the same answer a key rollover gets. The wire
// carries the two as one event.
//
// The unverified JWT locator is used only to select one issuer-owned publisher
// registration by exact header kid. The application resolves it once and hands
// it in. The engine checks the kid, verifies the exact compact token, gives the
// policy the verified origin beside the verified claims, and resolves unsigned
// issuerName/keyId only through that registration's opening-key view. Plain
// `resource` is diagnostic page data only.
//
// The engine reads the origin out of the verified token, like the renderId
// beside it, and checks it here for the one shape a browser can report. The
// origin is not part of any blob's coordinate. The application adapter
// compares it against the observed HTTP `Origin` before it reaches here.
// This engine refuses a render whose signed origin is not one a browser could
// ever have sent, so a value nothing could match never gets as far as a key.
//
// This engine asks what may be granted and then opens exactly that. It never
// turns a denial into a grant and never grants what the policy did not.
// Denying every coordinate a request
// asked for is one refusal, and the port answers 401, unless the host's
// "complete" not-delivered setting answers it with a no-key family report
// instead. Denying some of them is a
// 200 that carries the rest, which lets a publisher ship a name this issuer has
// not been told about without breaking the page around it.
//
// A policy is required: the constructor refuses an engine whose accessPolicy
// carries no decide(), because an issuer that grants from whatever the request
// carries has made no access decision at all. A library caller that wants to
// grant everything asked for injects AllowAllPolicy explicitly. The engine
// applies no such default when nothing is wired.
// Both sections go back when both were sent, which the format allows ("Mixed
// modes supported in same response"). A client that can cache prefers the
// periodKeys and never needs the contentKey; one that cannot ignores them.
//
// `policyData` comes back beside the keys and is the policy's opaque host data.
// The engine passes it through untouched and stores nothing.
//
// `notDelivered` names each presented access-group family this engine delivers
// nothing for, and why, as period keys Section 5.6 defines it. The engine reads the
// reason off the clamped decision it already made: no authorized desired
// coordinate is `denied`; an independently authorized selected coordinate
// without usable supply is `unavailable`. Denial is decided
// first, so it wins when both hold. A family whose granted period keys failed to
// open keeps its coordinate errors and gets no entry. The engine names only
// families the request presented in its own period sections, `periodKeys` or a
// period-capability source's section, because those are the families the
// client's association can check. `notDeliveredReport` is the host's disclosure
// setting. It changes what the engine says about a family and never what it
// grants.
//
// This engine answers presented coordinates: one presented sealed value per granted
// content-key or period-key coordinate. It reads no clock, because nothing it does
// is selected by an instant. An optional issuer behavior selected by an instant
// receives one host-captured epoch value in its per-unlock invocation context;
// the engine neither samples nor stores it.
//
// The engine accepts two composition seams, one per domain question. Both are
// narrow on purpose. A deployment may inject a `contentKeySource`: another way
// to produce one already-granted content key, asked per granted content name
// after the content-key seal has been tried and only while this issuer holds the
// opening key. It answers bytes, a miss or one error. A deployment may equally
// inject a `periodCapabilitySource`: another representation of one
// already-granted period capability. They are separate because the questions
// are: one produces a key at a coordinate this engine already names, the other
// names the periods of a reach only it can enumerate.
//
// The engine asks the period seam twice, in an order chosen to keep
// configuration out of the access decision. First it selects: given the granted access group and the
// count the policy answered, it names the coordinates it will represent, or
// misses. That runs where the decision is clamped, before any opening key is
// looked up, so it reaches no key material. Only a selection, or an ordinary
// period-key prefix, counts as something this deployment can answer, and the
// complete denial is counted from that. Then, once the opening-key state is
// resolved, the source represents what it selected and nothing else, under an
// opener confined to those same coordinates. Installing a source therefore
// changes neither the denial nor the reach into the opening keys.
//
// Across both seams, this engine keeps the access decision, and only the one
// opener reaches the opening key. The source's own request members, policy members,
// candidate order and geometry stay in the code that defines them. This engine
// names none of them.
//
// A content-key source is trusted issuer code, not a sandboxed plugin. The
// engine runs the common checks: the served name is granted, a direct seal's
// coordinate is that name, and an answer is bytes, a miss or one error. It
// cannot tell which auxiliary coordinate a mechanism may use for an item, or
// whether returned bytes are that item's key. Core Section 6.3 gives both
// duties to the source: it authorizes each auxiliary input under its
// mechanism, proves the result through that mechanism's authenticated binding,
// and never returns auxiliary period or chain bytes as an item key, because an
// item grant does not authorize their delivery.

import { base64urlEncode, utf8Encode } from "../core-shared/codec.js";
import { open as unseal } from "../core-shared--publisher-issuer/keySealing.js";
import { admitHeader, verify as verifyJwt } from "../core-shared--publisher-issuer/jwt.js";
import {
  BIND_DELIMITER,
  bindValue,
  validateRenderId,
} from "../core-shared--publisher-issuer/bind.js";
import { signableOrigin } from "../core-shared/publisherOrigin.js";
import {
  isAccessGroup,
  isContentName,
  isIssuerName,
  isUnicodeScalarString,
} from "../core-shared/names.js";
import { isPeriodKeyLabel } from "../core-shared/periodLabels.js";
import { periodGeometriesAgree } from "../core-shared/geometryBounds.js";
import { DcaError, dcaError } from "../core-shared/errors.js";
import { own, setOwn } from "../core-shared/wire.js";
import {
  DcaRequest,
  SEALED_FIELDS,
  sealedCandidates,
} from "../core-shared--client-issuer/DcaRequest.js";

// The checks an issuer runs before it touches a private key are pure: a request
// and a key go in, verified claims
// come out or a typed error is thrown. These checks know nothing about
// subscriptions. The AccessPolicy decides who may read what, and it runs after
// these checks pass.
//
// The order here is version, exact registration kid, signature, then renderId.
// The application selected the registration before calling core; core checks
// that the token names the same kid before using its verification key. Each
// step depends on the one before it. For example, a renderId read out of an
// unverified token anchors nothing.
//
// These checks run first because of the renderId. The publisher seals every
// blob of a render committed to that render and to the coordinate the blob is
// bound at, and the issuer rebuilds that commitment to open one. The issuer
// rebuilds from the signed renderId only, so a request whose signed renderId is
// missing, or is not the exact width `bind` requires, carries nothing that can
// be opened, and it is refused whole here rather than per blob.
//
// All three are defined here as functions, in that order. None of them reads a
// field of the engine. They are exported so the contract tests can pin the
// pre-private-key checks directly; the exports are not a granted public seam
// other issuers build on. They are defined in this module, and at migration
// they fold behind the reference-issuer contract bridge.

/** The format versions this code knows how to read, when none is injected. */
const SUPPORTED_VERSIONS = Object.freeze(["1"]);

/** Configuration this engine actually reads. The constructor rejects any other name. */
const OPTIONS = Object.freeze([
  "supportedVersions",
  "operatingIssuerNames",
  "accessPolicy",
  "developmentHttpOrigin",
  "contentKeySource",
  "contentKeyScope",
  "periodCapabilitySource",
  "notDeliveredReport",
  "responseSectionSources",
  "envelopeProcedures",
]);

/** Procedures `keySealing` opens itself; an extension cannot replace them. */
const BASE_ENVELOPE_PROCEDURES = Object.freeze(["ecdh-p256", "rsa-oaep"]);

/**
 * An extension's envelope procedure for 16-byte sealed keys: it opens one
 * sealed string under the held key and the BIND octets the engine built, and
 * answers the key bytes. A throw of `unseal_failed` is the ordinary per-item
 * refusal; any other throw is this issuer's fault.
 *
 * @typedef {(sealed: string, key: { privateKey: CryptoKey, publicKey?: CryptoKey }, aad: Uint8Array)
 *   => Promise<Uint8Array>} EnvelopeProcedure
 */

/**
 * An envelope procedure that names the key algorithms it opens under. The
 * engine then refuses, where it reads a key entry, an entry that permits the
 * procedure for a key of another algorithm.
 *
 * @typedef {{ open: EnvelopeProcedure, keyAlgorithms: string[] }} DeclaredEnvelopeProcedure
 */

/** Response members base writes; a section source may share only `periodGeometry`. */
const BASE_RESPONSE_MEMBERS = Object.freeze(["keys", "errors", "notDelivered"]);
/** The one response member several section sources may write, by equality. */
const SHARED_RESPONSE_MEMBER = "periodGeometry";

/**
 * The host's not-delivered disclosure settings. "none", the default, reports
 * nothing, so a host that says nothing sends today's answers byte for byte.
 * "partial" reports beside any result the request earns anyway and keeps a
 * complete denial a whole-request refusal. "complete" also answers a complete
 * denial that presented a reportable family with a no-key result naming it.
 */
const NOT_DELIVERED_REPORTS = Object.freeze(["none", "partial", "complete"]);

/** What an item that will not open reports, whichever coordinate carried it. */
const UNSEAL_FAILED = Object.freeze({
  error: "unseal_failed",
  message: "sealed value could not be opened",
});
const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;

/** The one width DCA v1 delivers a content key at. */
const CONTENT_KEY_BYTES = 16;

/**
 * The codes a composed content-key source may throw through this engine. Each
 * names an issuer fault: its configuration, its policy answer, or the opening
 * key the engine's own opener met. A source decides nothing about the request
 * or the caller, so a code that would tell the caller about either, such as
 * `denied`, cannot come from one.
 */
const SOURCE_FAULT_CODES = Object.freeze([
  "bad_config",
  "bad_policy",
  "bad_key",
  "unsupported_algorithm",
  "unsupported_option",
  "internal_error",
]);

/**
 * The verified claims of one request: the resource the publisher signed.
 *
 * @typedef {object} VerifiedClaims
 * @property {any} resource - the deeply frozen resourceJWT payload
 */

// Only a successful verification can mint this request-scoped provenance.
// The returned claims remain ordinary readable data; copying them does not copy
// provenance. Weak keys keep abandoned admissions from retaining request state.
/** @type {WeakMap<VerifiedClaims, { request: DcaRequest, token: string, key: CryptoKey, developmentHttpOrigin: boolean }>} */
const resourceVerifications = new WeakMap();

/** Freeze signed JSON without depending on the JavaScript call stack.
 * @param {any} value
 * @returns {void}
 */
function freezeVerifiedJson(value) {
  const pending = [value];
  for (let index = 0; index < pending.length; index++) {
    const current = pending[index];
    if (current === null || typeof current !== "object" || Object.isFrozen(current)) continue;
    Object.freeze(current);
    for (const member of Object.values(current)) pending.push(member);
  }
}

/** Consume before any await, including on a mismatched handoff.
 * @param {VerifiedClaims|undefined} verification
 * @param {DcaRequest} request
 * @param {CryptoKey} key
 * @param {boolean} developmentHttpOrigin
 * @returns {VerifiedClaims|null}
 */
function consumeResourceVerification(verification, request, key, developmentHttpOrigin) {
  if (verification === null || typeof verification !== "object") return null;
  const proof = resourceVerifications.get(verification);
  resourceVerifications.delete(verification);
  if (
    proof?.request !== request ||
    proof.token !== request.resourceJWT ||
    proof.key !== key ||
    proof.developmentHttpOrigin !== developmentHttpOrigin
  )
    return null;
  return verification;
}

/**
 * Require a `DcaRequest`; a plain document does not qualify. The fixed fields
 * could be read off either, so a raw object would pass version and envelope
 * checks and then contribute no coordinates at all. A caller that forgot to
 * construct one would get an empty answer rather than an error.
 *
 * @param {any} request
 * @returns {void}
 */
function requireRequest(request) {
  if (!(request instanceof DcaRequest)) {
    throw dcaError("bad_config", "these checks take a DcaRequest; parse or construct one first");
  }
}

/**
 * Forwarded from the markup, so it is the client's word for what the publisher
 * emitted. An issuer that cannot read a version must not guess at its shape.
 *
 * @param {DcaRequest} request
 * @param {readonly string[]} [supportedVersions]
 * @returns {void}
 */
export function checkVersion(request, supportedVersions = SUPPORTED_VERSIONS) {
  requireRequest(request);
  const version = request.version;
  if (typeof version !== "string" || !supportedVersions.includes(version)) {
    // Do not stringify an untrusted value here: it can be a deeply nested JSON
    // tree, and refusal must not turn into an uncaught RangeError.
    throw dcaError("bad_version", "unsupported version");
  }
}

/**
 * Check that the application supplied the registration selected by this token's
 * exact kid. Signature verification below establishes whether that registered
 * publisher signed the claims.
 *
 * The pairwise JWT module admits the header itself. That module defines the
 * fixed header pair and the `kid` rule and keeps them in one order. Core does
 * not repeat those three checks here: it has one registration in hand and the
 * question left is whether that registration answers this token's `kid`.
 *
 * @param {DcaRequest} request
 * @param {PublisherRegistration} registration
 * @returns {PublisherRegistration}
 */
export function publisherFor(request, registration) {
  const token = request.resourceJWT;
  if (typeof token !== "string") throw dcaError("bad_jwt", "the request carries no resourceJWT");
  const kid = admitHeader(token);
  if (registration === null || typeof registration !== "object" || registration.kid !== kid) {
    throw dcaError(
      "unknown_publisher_key",
      `no publisher registration for kid ${JSON.stringify(kid)}`,
    );
  }
  // The host selected a registration for this kid and built it without a key
  // or an opening store: its configuration is broken, and the request is not.
  if (!registration.publicKey || typeof registration.openingKeys?.get !== "function") {
    throw dcaError(
      "bad_config",
      "a publisher registration has a publicKey and an openingKeys store with get()",
    );
  }
  return registration;
}

/**
 * The `issuedAt` grammar: an RFC 3339 date-time whose offset is `Z`.
 *
 * This admits a format and reads no clock. The format calls `issuedAt` a
 * render timestamp for policy or diagnostics and gives it no expiry meaning,
 * so a render stamped last year is admitted here like one stamped this second.
 * The registered claims `iat` and `exp` stay unread beside it.
 */
const ISSUED_AT = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?[Zz]$/;

/**
 * @param {number} year
 * @param {number} month - 1 through 12
 * @returns {number}
 */
function daysInMonth(year, month) {
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  return [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
}

/**
 * The string must also name a real calendar date, and the arithmetic here
 * checks that. This code deliberately does not use `Date`: the host's ambient
 * clock and timezone do not define a signed string, and a test may remove the
 * constructor entirely.
 *
 * @param {unknown} issuedAt
 * @returns {boolean}
 */
function isIssuedAt(issuedAt) {
  if (typeof issuedAt !== "string") return false;
  const match = ISSUED_AT.exec(issuedAt);
  if (match === null) return false;

  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= daysInMonth(year, month) &&
    hour <= 23 &&
    minute <= 59 &&
    // RFC 3339 admits the leap second, so 60 is a second and 61 is not.
    second <= 60
  );
}

/**
 * The signature over the resource, and the renderId and origin under it.
 *
 * `publisherKey` is already selected by the exact `kid` in the resourceJWT
 * header. The caller owns the registration lookup because only it knows where
 * publisher registrations live.
 *
 * The envelope is not addressed to an issuer and does not need to be. Each
 * issuer holds its own keypair, so a render's blobs open under one private key
 * and nobody else's, and every blob of that render is bound to one signed copy
 * of the renderId.
 *
 * @param {DcaRequest} request
 * @param {CryptoKey} publisherKey - ECDSA P-256 public key
 * @param {boolean} [developmentHttpOrigin] - this issuer's development profile,
 *   which admits a signed http origin on a loopback host and on nothing else
 * @returns {Promise<VerifiedClaims>}
 */
export async function checkEnvelopes(request, publisherKey, developmentHttpOrigin = false) {
  requireRequest(request);

  const resourceToken = request.resourceJWT;
  if (typeof resourceToken !== "string")
    throw dcaError("bad_jwt", "the request carries no resourceJWT");

  const resource = await verifyJwt(resourceToken, publisherKey);

  const renderId = own(resource, "renderId");
  if (typeof renderId !== "string" || renderId.length === 0) {
    throw dcaError(
      "binding_failed",
      "the signed resource carries no renderId to bind these blobs to",
    );
  }
  validateRenderId(renderId);

  // The value the application compared the observed HTTP Origin with, read
  // against the origins this issuer will answer at all. A render whose signed
  // origin is not the canonical serialization names a delivery no browser can
  // report; one signing http names a delivery a production render never has,
  // and a browser that reports the same bytes makes the comparison agree
  // without making the delivery admissible. Both are refused whole rather than
  // per blob, so a matching pair of http bytes never reaches an opening key.
  //
  // `developmentHttpOrigin` is this issuer's explicit development profile,
  // the same opt-in the publisher's Sealer takes and the same loopback host
  // set: turning it on does not admit `http://www.news-site.example`.
  const origin = own(resource, "origin");
  if (typeof origin !== "string" || signableOrigin(origin, developmentHttpOrigin) !== origin) {
    throw dcaError(
      "bad_jwt",
      "the signed resource carries no canonical origin to admit this delivery at",
    );
  }

  // The three members left. The whole verified payload travels on to policy,
  // so a required member this step never looked at would arrive at a
  // decision unadmitted, carrying whatever the publisher happened to sign.
  // Each one is refused whole: one token holds every coordinate of the
  // request, so there is no single blob a malformed claim belongs to.
  const issuedAt = own(resource, "issuedAt");
  if (!isIssuedAt(issuedAt)) {
    throw dcaError("bad_jwt", "the signed resource carries no RFC 3339 issuedAt with a Z offset");
  }

  const resourceId = own(resource, "resourceId");
  if (!isUnicodeScalarString(resourceId) || resourceId.length === 0) {
    throw dcaError("bad_jwt", "the signed resource carries no resourceId to decide on");
  }

  const data = own(resource, "data");
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw dcaError("bad_jwt", "the signed resource carries no data object to decide on");
  }

  freezeVerifiedJson(resource);
  const claims = Object.freeze({ resource });
  resourceVerifications.set(claims, {
    request,
    token: resourceToken,
    key: publisherKey,
    developmentHttpOrigin,
  });
  return claims;
}

/**
 * @typedef {object} UnlockResult
 * @property {{ contentName: string, key: string }[]} contentKeys - base64url raw
 *   key bytes; several records at one contentName are distinct candidates
 * @property {{ accessGroup: string, period: string, key: string }[]} periodKeys -
 *   base64url raw key bytes; several records at one coordinate are distinct candidates
 * @property {{ kind: string, accessGroup: string, entries: { t: string, key: string }[], interpretation: any }[]} capabilities -
 *   represented period capabilities, one distinct candidate per entry. The
 *   engine preserves the source-declared kind and interpretation; the
 *   processor's configured encoder names the wire section.
 * @property {{ coordinate: string, error: string, message: string }[]} errors -
 *   one record per failed coordinate, none where a candidate produced a key
 * @property {{ accessGroup: string, reason: 'denied'|'unavailable' }[]} notDelivered -
 *   presented access-group families this unlock delivers nothing for, one
 *   record each; empty when the host reports none
 * @property {any} policyData - opaque host data from the access policy
 * @property {Record<string, unknown>} [sections] - the presented section
 *   sources' response members, by member name
 */

/**
 * @typedef {object} PolicyPeriodGrant
 * @property {string} accessGroup
 * @property {string[]} [periods] - explicitly authorized ordinary period labels
 * @property {number} [futurePeriodCount] - independent capability route's optional future horizon
 * @property {(t: string) => boolean} [authorizePeriod] - trusted reusable-period authorization;
 *   limits on future article coordinates must be enforced here independently
 *   of futurePeriodCount, which bounds only the optional future horizon
 */

/**
 * @typedef {object} PolicyDecision
 * @property {string[]} [contentNames]
 * @property {PolicyPeriodGrant[]} [periodGrants]
 * @property {any} [policyData]
 */

/**
 * The `principal` and `context` an issuer host passes to `unlock`. The host
 * authenticates the caller before this point, and the engine reads neither
 * member out of the request.
 *
 * @typedef {object} IssuerHostPolicyInput
 * @property {object|null} [principal] - the caller the host authenticated
 * @property {any} [context] - opaque issuer-owned state the policy interprets
 */

/**
 * What one policy decision is made against: the host members above, plus the
 * publisher origin. The engine fills `publisher.origin` in from the verified
 * `resourceJWT.origin`, after `checkEnvelopes` has checked the publisher
 * signature over the resource and validated that origin's canonical
 * serialization. A caller passes host members only, so it can neither supply
 * nor overwrite this coordinate.
 *
 * @typedef {object} IssuerPolicyDecisionInput
 * @property {object|null} principal - the caller the host authenticated, `null` when it named none
 * @property {any} context - the host's opaque policy context, `undefined` when it passed none
 * @property {{ origin: string }} publisher - the verified signed publisher context origin from the
 *   resource JWT; matching it against the observed HTTP Origin belongs to the browser binding
 *   the application composes, before this engine is called
 */

/**
 * Who may read what. The caller injects it, because the spec assigns this
 * decision to the issuer. It is duck-typed, so the demo's naive policy plugs
 * into the same seam as a strict one.
 *
 * @typedef {object} AccessPolicy
 * @property {(claims: any, requested: { contentNames: string[], accessGroups: string[], periodCoordinates: Record<string, string[]>, sourcePeriodCoordinates?: Record<string, string[]> }, input: IssuerPolicyDecisionInput) => (PolicyDecision|Promise<PolicyDecision>)} decide -
 *   answers granted `contentNames` and `periodGrants`, a list of
 *   base `{ accessGroup, periods }` or independent capability grants with
 *   `futurePeriodCount` and a trusted `authorizePeriod(t)` boolean decision.
 *   A returned `{}` is a completed denial. If no decision is available, throw
 *   `dcaError('policy_unavailable')`; unexpected exceptions are server faults.
 */

/**
 * A held entry registers its ordinary envelope procedure as `algorithm`,
 * `ecdh-p256` or `rsa-oaep` and never an extension procedure. Its
 * optional `envelopes` is an allowlist of the procedures the key may open
 * under: absent, the ordinary procedure only; `["ecdh-p256", "compact-ecdh"]`,
 * both; `["compact-ecdh"]`, the extension procedure only, so a request without
 * an `envelope` member opens nothing. A request selects an extension procedure
 * with its `envelope` member; such a procedure may need the key's `publicKey`
 * as well.
 *
 * @typedef {{ algorithm: string, privateKey: CryptoKey, publicKey?: CryptoKey, envelopes?: string[] }|{ retired: true }} IssuerKeyEntry
 */

/**
 * The private key for one issuerName and keyId. Duck-typed on purpose: a real
 * issuer looks this up wherever it keeps keys.
 *
 * A store gives one of three answers, and a rollover needs the third.
 * `undefined` means this issuer never held the keyId. An entry with a
 * `privateKey` means it holds the key. `{ retired: true }` means it held the key
 * and has let it go. In that case the markup outlived the key. That is an
 * operational failure, not an integrity failure, so the engine answers it per
 * item rather than refusing the whole request.
 *
 * @typedef {object} KeyStore
 * @property {(issuerName: string, keyId: string) => (IssuerKeyEntry|undefined|Promise<IssuerKeyEntry|undefined>)} get
 */

/**
 * One signing-key entry, not the publisher's entire registration set. During
 * rotation the host may retain several entries with distinct kids and the same
 * publisher scope; each verified request selects exactly one entry.
 * @typedef {object} PublisherRegistration
 * @property {string} kid - the exact resourceJWT header kid this registration answers
 * @property {CryptoKey} publicKey - the publisher's resource-signing key: an
 *   ECDSA P-256 public key with `verify` usage. Another kind is a host
 *   configuration fault (`bad_config`), not the request's `bad_signature`.
 * @property {string[]} [origins] - an optional issuer-held limit on the browser
 *   origins this publisher may be served from. The signed `resourceJWT.origin`
 *   governs; this list is defense in depth the application checks after that
 *   comparison, and a registration may carry none.
 * @property {KeyStore} openingKeys - issuer opening keys visible to this publisher
 */

/**
 * The opening key this request's registration resolved to, and whether the
 * registration answered a retirement instead.
 *
 * @typedef {{ retired: boolean, key: { algorithm: string, privateKey: CryptoKey, publicKey?: CryptoKey, envelopes?: unknown } }} OpeningKeyState
 */

/**
 * What the policy granted, already clamped to what the request presented.
 *
 * @typedef {object} GrantedCoordinates
 * @property {string[]} contentNames
 * @property {{ accessGroup: string, periods: string[] }[]} periodKeyGrants
 * @property {{ accessGroup: string, periodCount: number, route: PeriodRoute, authorizedPeriods?: string[] }[]} periodCapabilities -
 *   the granted period reach per access group and the representation route the
 *   composition selected before opening-key work
 * @property {number} asked - how many coordinate families the request presented
 * @property {number} granted - how many authorized coordinates have a selected delivery route
 * @property {{ accessGroup: string, reason: 'denied'|'unavailable' }[]} notDelivered -
 *   each reportable presented family that has no delivery route, by reason
 * @property {any} policyData
 * @property {any} decision - the whole policy answer, read here for the members
 *   above and handed on unread to a content-key source that added its own
 */

/**
 * One content key, or the reason there is none. A source answers with bytes,
 * with a miss that leaves whatever failure already stands, or with the one
 * failure this item reports when nothing else answers it. There is no third
 * shape and no response section: a source produces one already-granted content
 * key and nothing else.
 *
 * @typedef {{ bytes: Uint8Array }|{ miss: true }|{ error: { error: string, message: string } }} ContentKeyAnswer
 */

/**
 * What one unlock hands a content-key source. Every member is one of three
 * things: the request, which carries the source's own grammar; the decision,
 * which carries the source's own policy additions; or a capability this engine
 * keeps authority over:
 *
 * - `scope` is the opaque, host-selected source view for the authenticated
 *   publisher registration. The engine selects it only when an authorized
 *   ordinary content-key seal fails under an active opening key; the source
 *   never receives the registration or its opening-key view.
 * - `renderId` is the verified render anchor, out of the signed resource.
 * - `open` is the one opening operation, closed over that anchor and over the
 *   key state this request resolved to. It returns bytes or a typed failure,
 *   and it is the only way a source reaches the opening key. A direct content
 *   seal names its own granted content coordinate. An auxiliary envelope may
 *   use its native binding coordinate while separately naming the final-granted
 *   content item it serves. The engine checks that name against the grant and
 *   opens the auxiliary coordinate as given; it does not check that the
 *   mechanism permits that coordinate for that item. The source does.
 *
 * @typedef {object} ContentKeyUnlock
 * @property {DcaRequest} request
 * @property {any} decision - the whole policy answer
 * @property {any} scope
 * @property {string} renderId
 * @property {(sealed: unknown, bindingCoordinate: { contentName: string }|{ accessGroup: string, t: string }, forContentName?: string)
 *   => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>} open
 */

/**
 * Another way to produce one already-granted content key.
 *
 * After an authorized ordinary content-key seal fails under an active opening
 * key, the engine selects the opaque scope and calls `contentKeys` once for
 * that unlock. It then asks the returned lookup for each granted content name
 * whose ordinary seal failed. It never asks about periods and files only its
 * answer under that content name. `presented` adds coordinates the policy may
 * decide on, and the decision is still the policy's.
 *
 * The source is trusted issuer code. Under core Section 6.3 it selects its
 * auxiliary inputs from the admitted presented coordinates or from issuer-held
 * material scoped to the authenticated registration, authorizes each one for
 * the granted item under its mechanism, and returns bytes only when that
 * mechanism's authenticated binding shows they are the item's content key for
 * this render. It never returns an auxiliary period or chain key as the
 * answer: an item grant does not authorize delivering one. The engine does not
 * enforce these duties; a source that breaks them makes the issuer
 * nonconforming.
 *
 * @typedef {object} ContentKeySource
 * @property {(request: DcaRequest) => { contentNames?: string[], accessGroups?: string[], sourcePeriodCoordinates?: Record<string, string[]> }} [presented] -
 *   coordinates this request carries that the ordinary reading does not see.
 *   Presenting grants nothing.
 * @property {(unlock: ContentKeyUnlock) => ((contentName: string) => Promise<ContentKeyAnswer>)} contentKeys -
 *   what this source can produce for one unlock, as a lookup by granted content
 *   name. Called lazily after a non-retirement ordinary seal failure, once per
 *   unlock; the returned lookup is called for each failed granted name
 */

/**
 * A coordinate a sealed value is bound at, in the grammar
 * `core-shared--publisher-issuer/bind.js` owns and validates. This engine's own
 * routes name a contentName, or an accessGroup with its t; a composed source
 * names whatever that grammar admits, and the grammar refuses the rest.
 *
 * @typedef {Omit<import('../core-shared--publisher-issuer/bind.js').Binding, 'renderId'>} BoundCoordinate
 */

/**
 * One coordinate a source said it will represent, named while the decision was
 * being clamped and before any opening key was read. The label is the one this
 * engine confines that source's opener to; a source may carry members of its
 * own beside it, which this engine passes back unread.
 *
 * @typedef {object} PeriodSelection
 * @property {string} t - the period label, under either selected kind. A chain
 *   coordinate carries it as `suppliedT` once it becomes a binding
 * @property {boolean} [chainKey] - absent or false selects the period-key
 *   BIND kind; true selects the chain-key BIND kind
 * @property {number} [chainsPerDay] - authenticated chain geometry when the
 *   selected kind is chain-key
 * @property {number} [periodMinutes] - authenticated chain geometry when the
 *   selected kind is chain-key
 */

/**
 * What a source answers when it is asked which of a granted capability it will
 * represent. A selection names at least one coordinate. A miss declines the
 * group and leaves it to this engine's period-key route. `unavailable: true` means
 * the composition is responsible for the group's period representation but
 * does not select an output; `unavailable: "unavailable"` additionally
 * attests that valid supply cannot provide any independently authorized
 * selected coordinate. Malformed supply, response-form incompatibility and
 * capacity omission do not establish this condition. The period-key output
 * route stays closed in either case. The three
 * shapes are exclusive, and only a selection or an independently available
 * period-key prefix counts as a grant.
 *
 * @typedef {{ selected: PeriodSelection[] }|{ miss: true }|{ unavailable: true|'unavailable'|'denied' }} PeriodSelectionAnswer
 */

/**
 * The normalized period route for one granted access group.
 *
 * @typedef {{ kind: 'selected', selected: PeriodSelection[] }
 *   | { kind: 'period-keys' }
 *   | { kind: 'authorized-unavailable' }
 *   | { kind: 'unavailable' }
 *   | { kind: 'denied' }} PeriodRoute
 */

/**
 * One period of a granted capability, in the representation a source answers
 * with: the label it is delivered under and its key bytes, or the one failure
 * that label reports. Exactly one of the two, because a period that opened and
 * failed is not an answer.
 *
 * @typedef {{ t: string, bytes: Uint8Array }
 *   | { t: string, error: { error: string, message: string } }} PeriodRepresentation
 */

/**
 * One selected capability, as a source represents it once the opening key is
 * resolved: the periods it produced, each of them bytes or a failure under a
 * label. There is no miss here and no empty answer. Only the selection step
 * can miss, and a coordinate this deployment counted as granted reports either
 * a key or the reason there is none.
 *
 * @typedef {{ kind: string, interpretation: any, periods: PeriodRepresentation[] }} PeriodCapabilityAnswer
 */

/**
 * What one unlock hands a period-capability source. Preparation and output
 * accounting belong to this invocation, even when the request object is reused:
 *
 * - `request` carries this source's own grammar.
 * - `periodKeyCount` reserves actual deduplicated ordinary fallback output.
 * - `selectedCapabilities` is the complete immutable list of authorized source
 *   selections. Their payloads remain opaque to base; the source can reserve
 *   mandatory output across every family before admitting optional output.
 * - `open` is the one opening operation, closed over the verified render anchor
 *   and the key state this request resolved to, and confined to the coordinates
 *   this source selected. It returns bytes or a typed failure, and this view
 *   carries no other route to the opening key.
 *
 * A source holding long-lived material of its own would need the authenticated
 * registration to select it by, the way a content-key source does. None does,
 * so this view carries no registration to select anything with.
 *
 * @typedef {object} PeriodCapabilityUnlock
 * @property {DcaRequest} request
 * @property {number} periodKeyCount - actual deduplicated ordinary fallback
 *   output already reserved for this invocation
 * @property {readonly { accessGroup: string, selected: readonly PeriodSelection[] }[]} selectedCapabilities -
 *   complete authorized source selections; payloads remain opaque to base
 * @property {(sealed: unknown, coordinate: BoundCoordinate)
 *   => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>} open
 */

/**
 * @typedef {object} IssuerInvocationContext
 * @property {number} [capturedAtMs] - finite host-captured epoch milliseconds;
 *   sources that select time-dependent capabilities receive it but never a
 *   host clock
 */

/** Host-only verification handoff, never passed to capability sources.
 * @typedef {IssuerInvocationContext & { verification?: VerifiedClaims }} IssuerUnlockInvocation
 */

/**
 * Another representation of one already-granted period capability, in two
 * steps. `selection` runs while the decision is clamped and before any opening
 * key is looked up. It names the coordinates it will represent, declines to
 * the period-key route, or permits no output. `capabilities` runs after opening-key
 * state is resolved and represents only those selected coordinates.
 *
 * A represented group is answered by this source alone; its period keys are
 * not also opened. Which groups a source selects belongs to the source and its
 * composition, not to a flag this engine reads.
 *
 * @typedef {object} PeriodCapabilitySource
 * @property {(request: DcaRequest, invocation: IssuerInvocationContext) => { accessGroups?: string[] }} [presented] -
 *   access groups this request carries that the ordinary reading does not see.
 *   Presenting grants nothing.
 * @property {(request: DcaRequest, invocation: IssuerInvocationContext, grants?: PolicyPeriodGrant[]) => ((accessGroup: string, periodCount: number, grant?: PolicyPeriodGrant)
 *   => PeriodSelectionAnswer)} selection - which coordinates of a granted
 *   capability this source will represent, answered before any opening key
 * @property {(unlock: PeriodCapabilityUnlock, invocation: IssuerInvocationContext) => ((accessGroup: string, selected: PeriodSelection[])
 *   => Promise<PeriodCapabilityAnswer|{ kind: "omitted" }>)} capabilities - what this source
 *   represents for one unlock, as a lookup by granted access group. An explicit
 *   `{ kind: "omitted" }` produces no output after optional-output clamping;
 *   mandatory output still refuses the exchange if it cannot fit.
 * @property {(count: number) => void} [checkPeriodKeyOutput] - synchronous
 *   postcondition on the final deduplicated ordinary period-key record count,
 *   including base fallback. Returns undefined or throws; receives no keys.
 */

/**
 * What one unlock hands a response section source. The source reads its own
 * request members, decides with its own policy and opens its own envelopes
 * through `openAuxiliary`; it never receives the registration, the opening-key
 * view or a private key.
 *
 * - `claims` is a frozen copy of the verified resource JWT payload.
 * - `policyInput` is the decision input the base policy receives: the host's
 *   principal and context and the verified publisher origin.
 * - `openAuxiliary(sealed, { aad })` opens one envelope under the opening key
 *   this request resolves to, with the source's opener for the envelope
 *   procedure the engine selected for that key. The source names only its
 *   AAD; it cannot name a procedure. The key resolves lazily on the first
 *   permitted open and is shared by the rest of this unlock. It answers bytes
 *   or a typed failure; a retired key answers the retirement.
 *
 * @typedef {object} ResponseSectionUnlock
 * @property {DcaRequest} request
 * @property {any} claims
 * @property {Readonly<IssuerPolicyDecisionInput>} policyInput
 * @property {IssuerInvocationContext} invocation
 * @property {(sealed: unknown, envelope: { aad: Uint8Array })
 *   => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>} openAuxiliary
 */

/**
 * A selected extension's own response members. The engine asks `presented`
 * for each request; a presented source is answered after the base coordinates
 * and before the response is returned, and its members follow every base
 * member. A source that throws refuses the whole request, so no base key of
 * that exchange leaves either. A source that answers `{}` granted nothing; the
 * engine refuses the request as denied when neither base nor any source
 * granted anything.
 *
 * @typedef {object} ResponseSectionSource
 * @property {string} name
 * @property {string[]} members - the response members it may write; never
 *   `keys`, `errors` or `notDelivered`. `periodGeometry` must equal any other
 *   writer's.
 * @property {(request: DcaRequest) => boolean} presented
 * @property {Record<string, (sealed: unknown, privateKey: CryptoKey, aad: Uint8Array) => Promise<Uint8Array>>} [envelopeOpeners] -
 *   the source's payload contract per base envelope procedure (`ecdh-p256`,
 *   `rsa-oaep`); the engine selects which one runs, and only it hands over
 *   the private key
 * @property {(unlock: ResponseSectionUnlock) => Promise<Record<string, unknown>>} respond
 */

/**
 * The engine copies and freezes a response source's declared metadata, while
 * capturing `presented` and `respond` as callbacks on the original source
 * object. It calls both with that original object as `this`; reassigning either
 * property after engine construction does not replace the captured callback,
 * and the source object itself remains mutable.
 */

/**
 * @param {unknown} value
 * @returns {readonly Required<ResponseSectionSource>[]}
 */
function checkedSectionSources(value) {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value)) {
    throw dcaError("bad_config", "responseSectionSources is a list of section sources");
  }
  /** @type {Map<string, string>} */
  const owners = new Map();
  const names = new Set();
  return Object.freeze(
    value.map((source) => {
      const candidate = /** @type {any} */ (source);
      const presented = candidate?.presented;
      const respond = candidate?.respond;
      if (
        source === null ||
        typeof source !== "object" ||
        typeof source.name !== "string" ||
        source.name === "" ||
        typeof presented !== "function" ||
        typeof respond !== "function"
      ) {
        throw dcaError(
          "bad_config",
          "a response section source has a name, presented(request) and respond(unlock)",
        );
      }
      if (names.has(source.name)) {
        throw dcaError("bad_config", `the section source ${source.name} is listed twice`);
      }
      names.add(source.name);
      const members = source.members;
      if (
        !Array.isArray(members) ||
        members.length === 0 ||
        members.some((member) => typeof member !== "string" || member === "")
      ) {
        throw dcaError("bad_config", `${source.name} declares its response members as a list`);
      }
      for (const member of members) {
        if (BASE_RESPONSE_MEMBERS.includes(member)) {
          throw dcaError("bad_config", `${source.name} declares ${member}, which base writes`);
        }
        const other = owners.get(member);
        if (other !== undefined && member !== SHARED_RESPONSE_MEMBER) {
          throw dcaError(
            "bad_config",
            `the response member ${member} is declared by ${other} and by ${source.name}`,
          );
        }
        owners.set(member, source.name);
      }
      const openers = source.envelopeOpeners ?? {};
      if (
        openers === null ||
        typeof openers !== "object" ||
        Array.isArray(openers) ||
        Object.values(openers).some((open) => typeof open !== "function")
      ) {
        throw dcaError("bad_config", `${source.name} declares envelope openers by procedure`);
      }
      /** @type {Required<ResponseSectionSource>} */
      const checked = {
        name: source.name,
        members: [...members],
        presented: (request) => Reflect.apply(presented, source, [request]),
        envelopeOpeners: Object.freeze({ ...openers }),
        respond: (unlock) => Reflect.apply(respond, source, [unlock]),
      };
      Object.freeze(checked.members);
      return Object.freeze(checked);
    }),
  );
}

/**
 * A frozen deep copy of a verified JSON payload.
 *
 * @param {any} value
 * @returns {any}
 */
function frozenCopy(value) {
  if (value === null || typeof value !== "object") return value;
  const copy = Array.isArray(value)
    ? value.map(frozenCopy)
    : Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, frozenCopy(entry)]));
  return Object.freeze(copy);
}

/**
 * A response section gets the same host-owned policy snapshot and authenticated
 * publisher record as the base policy, without recursively copying opaque
 * host values such as principal objects, Maps, or service handles.
 *
 * @param {IssuerPolicyDecisionInput} input
 * @returns {Readonly<IssuerPolicyDecisionInput>}
 */
function frozenPolicyInput(input) {
  return Object.freeze({
    ...input,
    publisher: Object.freeze({ ...input.publisher }),
  });
}

/**
 * Copy the one host context a source may observe so a source cannot retain or
 * mutate caller-owned state across unlocks. Period-key-only engines deliberately do
 * not require a timestamp.
 *
 * @param {any} value
 * @returns {IssuerInvocationContext}
 */
function invocationContext(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw dcaError("bad_config", "issuer invocation context is an object");
  }
  for (const name of Object.keys(value)) {
    if (name !== "capturedAtMs" && name !== "verification") {
      throw dcaError("bad_config", `issuer invocation context has no ${name}`);
    }
  }
  if (!Object.hasOwn(value, "capturedAtMs")) return Object.freeze({});
  if (
    typeof value.capturedAtMs !== "number" ||
    !Number.isFinite(value.capturedAtMs) ||
    Math.abs(value.capturedAtMs) > MAX_DATE_EPOCH_MS
  ) {
    throw dcaError(
      "bad_config",
      "capturedAtMs is a finite host-captured epoch millisecond within Date range",
    );
  }
  return Object.freeze({ capturedAtMs: value.capturedAtMs });
}

export class IssuerEngine {
  /** @type {string[]} */
  #supportedVersions;
  /** @type {Set<string>} */
  #operatingIssuerNames;
  /** @type {AccessPolicy} */
  #accessPolicy;

  /** @type {boolean} */
  #developmentHttpOrigin;

  /** @type {ContentKeySource|null} */
  #contentKeySource;

  /** @type {((registration: PublisherRegistration) => any|Promise<any>)|null} */
  #contentKeyScope;

  /** @type {PeriodCapabilitySource|null} */
  #periodCapabilitySource;

  /** @type {((count: number) => void)|null} */
  #checkPeriodKeyOutput;

  /** @type {'none'|'partial'|'complete'} */
  #notDeliveredReport;

  /** @type {readonly Required<ResponseSectionSource>[]} */
  #sectionSources;

  /** @type {Readonly<Record<string, EnvelopeProcedure>>} */
  #envelopeProcedures;

  /** @type {Readonly<Record<string, readonly string[]>>} */
  #envelopeKeyAlgorithms;

  /**
   * Refuse names outside the trusted receiving endpoint's operating scope.
   * The processor calls this during admission so a host response-cache hit
   * cannot skip the scope check; unlock repeats it for direct library callers.
   *
   * @param {DcaRequest} request
   */
  checkOperatingIssuerName(request) {
    if (!(request instanceof DcaRequest)) {
      throw dcaError("bad_config", "issuer-name scope checks take a DcaRequest");
    }
    if (
      typeof request.issuerName !== "string" ||
      !this.#operatingIssuerNames.has(request.issuerName)
    ) {
      throw dcaError(
        "out_of_scope_issuer",
        `this endpoint does not operate issuer name ${JSON.stringify(request.issuerName)}`,
      );
    }
  }

  /**
   * @param {object} config
   * @param {string[]} [config.supportedVersions] - what this issuer can read
   * @param {string[]} config.operatingIssuerNames - distinct issuer names this
   *   endpoint serves under this policy and each registration-scoped key view
   * @param {AccessPolicy} config.accessPolicy - who may read what. Required:
   *   signature verification authenticates the publisher but does not grant
   *   the caller any key.
   * @param {boolean} [config.developmentHttpOrigin] - the development
   *   profile, which admits a signed http origin on a loopback host and on
   *   nothing else. Off unless a deployment says otherwise, so a production
   *   issuer answers https renders only. Same name and same host set as the
   *   publisher's `Sealer` option, because it is the same profile read from
   *   the other end.
   * @param {ContentKeySource} [config.contentKeySource] - another way to
   *   produce one already-granted content key, for a deployment that composes
   *   one. Absent, this engine answers the content-key seals alone.
   * @param {(registration: PublisherRegistration) => any|Promise<any>} [config.contentKeyScope] -
   *   issuer-host selection of one opaque view for a composed content-key
   *   source. It receives the authenticated registration, never request
   *   labels or a raw signing kid, and runs once per unlock only after an
   *   authorized ordinary content-key seal fails under an active opening key.
   * @param {PeriodCapabilitySource} [config.periodCapabilitySource] - another
   *   representation of one already-granted period capability, for a
   *   deployment that composes one. It selects before the opening keys are
   *   read and represents after. Absent, this engine answers the presented period
   *   keys alone.
   * @param {'none'|'partial'|'complete'} [config.notDeliveredReport] - which
   *   period keys Section 5.6 family reports this issuer discloses. "none", the
   *   default, reports nothing; "partial" reports beside a result the request
   *   earns anyway; "complete" also answers a complete denial with a no-key
   *   report.
   * @param {ResponseSectionSource[]} [config.responseSectionSources] - selected
   *   extensions' own response members, answered after the base coordinates
   * @param {Record<string, EnvelopeProcedure|DeclaredEnvelopeProcedure>} [config.envelopeProcedures] -
   *   selected extensions' envelope procedures by name; a request selects one
   *   with `envelope` only where its key entry permits it
   */
  constructor(config) {
    for (const name of Object.keys(config ?? {})) {
      if (!OPTIONS.includes(name)) {
        throw dcaError(
          "unsupported_option",
          `IssuerEngine has no ${name} yet, and will not pretend to`,
        );
      }
    }

    const {
      supportedVersions,
      operatingIssuerNames,
      accessPolicy,
      developmentHttpOrigin = false,
      contentKeySource,
      contentKeyScope,
      periodCapabilitySource,
      notDeliveredReport = "none",
      responseSectionSources,
      envelopeProcedures = {},
    } = config ?? {};
    if (typeof accessPolicy?.decide !== "function") {
      throw dcaError(
        "bad_config",
        "an accessPolicy is an object with a decide(claims, requested, input)",
      );
    }
    if (
      !Array.isArray(operatingIssuerNames) ||
      operatingIssuerNames.length === 0 ||
      operatingIssuerNames.some((name) => !isIssuerName(name)) ||
      new Set(operatingIssuerNames).size !== operatingIssuerNames.length
    ) {
      throw dcaError(
        "bad_config",
        "operatingIssuerNames is a nonempty list of distinct issuer names this endpoint serves",
      );
    }
    if (typeof developmentHttpOrigin !== "boolean") {
      throw dcaError("bad_config", "developmentHttpOrigin is a profile that is on or off");
    }
    if (contentKeySource !== undefined && typeof contentKeySource?.contentKeys !== "function") {
      throw dcaError("bad_config", "a contentKeySource is an object with a contentKeys(unlock)");
    }
    if (contentKeyScope !== undefined && typeof contentKeyScope !== "function") {
      throw dcaError(
        "bad_config",
        "a contentKeyScope selects an opaque view from the authenticated registration",
      );
    }
    if (
      periodCapabilitySource !== undefined &&
      (typeof periodCapabilitySource?.selection !== "function" ||
        typeof periodCapabilitySource.capabilities !== "function")
    ) {
      throw dcaError(
        "bad_config",
        "a periodCapabilitySource is an object with a selection(request) and a capabilities(unlock)",
      );
    }

    if (!NOT_DELIVERED_REPORTS.includes(notDeliveredReport)) {
      throw dcaError(
        "bad_config",
        `notDeliveredReport is one of ${NOT_DELIVERED_REPORTS.join(", ")}`,
      );
    }

    const checkPeriodKeyOutput = periodCapabilitySource?.checkPeriodKeyOutput;
    if (checkPeriodKeyOutput !== undefined && typeof checkPeriodKeyOutput !== "function") {
      throw dcaError("bad_config", "a period output check is a synchronous function");
    }

    this.#supportedVersions = [...(supportedVersions ?? SUPPORTED_VERSIONS)];
    this.#operatingIssuerNames = new Set(operatingIssuerNames);
    this.#accessPolicy = accessPolicy;
    this.#developmentHttpOrigin = developmentHttpOrigin;
    this.#contentKeySource = contentKeySource ?? null;
    this.#contentKeyScope = contentKeyScope ?? null;
    this.#periodCapabilitySource = periodCapabilitySource ?? null;
    this.#checkPeriodKeyOutput = checkPeriodKeyOutput?.bind(periodCapabilitySource) ?? null;
    this.#notDeliveredReport = notDeliveredReport;
    this.#sectionSources = checkedSectionSources(responseSectionSources);
    const procedures = checkedEnvelopeProcedures(envelopeProcedures);
    this.#envelopeProcedures = procedures.openers;
    this.#envelopeKeyAlgorithms = procedures.keyAlgorithms;
  }

  /**
   * What the policy allows, out of what the request actually presented. The
   * decision is read here and nowhere else, so a policy answering with
   * something that is not a decision is a server fault rather than a grant.
   *
   * Ordinary period grants name exact labels and are intersected with the
   * request's own sealed period labels. A selected capability source can
   * represent those same authorized labels using another supplied route. An
   * independent chain grant uses its separate trusted future-horizon form.
   *
   * @param {DcaRequest} request
   * @param {any} claims - the verified payload and the publisher it belongs to
   * @param {IssuerPolicyDecisionInput} policyInput - the host members plus the
   *   verified `resourceJWT.origin` this engine filled in
   * @param {IssuerInvocationContext} invocation
   * @returns {Promise<GrantedCoordinates>}
   */
  async #decide(request, claims, policyInput, invocation) {
    // Admission already checked every record. Several records at one
    // coordinate present it once. The decision needs coordinates only, so no
    // envelope is read here.
    const none = () => false;
    const sealedContentKeys = sealedCandidates(
      request.sealedContentKeys,
      SEALED_FIELDS.contentKeys,
      none,
    );
    const sealedPeriodKeys = sealedCandidates(
      request.sealedPeriodKeys,
      SEALED_FIELDS.periodKeys,
      none,
    );

    // A composed content-key source may see coordinates in members of its
    // own that this engine does not read. They join the presented set the
    // decision chooses out of, and nothing else: a coordinate is still
    // opened only where the policy said yes to it.
    let described;
    try {
      described = this.#contentKeySource?.presented?.(request) ?? {};
    } catch (cause) {
      throw contentKeySourceFault(cause);
    }
    /** Source-only labels never expand the ordinary period grant route. */
    const sourcePeriodCoordinates = {};
    const sourceLabels = described.sourcePeriodCoordinates;
    if (sourceLabels !== undefined) {
      if (sourceLabels === null || typeof sourceLabels !== "object" || Array.isArray(sourceLabels))
        throw dcaError("bad_config", "source period coordinates must be a record");
      for (const [group, labels] of Object.entries(sourceLabels)) {
        if (
          !isAccessGroup(group) ||
          !Array.isArray(labels) ||
          labels.some((t) => !isPeriodKeyLabel(t))
        )
          throw dcaError("bad_config", "invalid source period coordinates");
        setOwn(sourcePeriodCoordinates, group, [...new Set(labels)].sort());
      }
    }
    const describedPeriods = this.#periodCapabilitySource?.presented?.(request, invocation) ?? {};
    const presentedByPeriodSource = presentedNames(describedPeriods.accessGroups, "accessGroups");
    const presentedContent = [
      ...new Set([
        ...sealedContentKeys.keys(),
        ...presentedNames(described.contentNames, "contentNames"),
      ]),
    ];
    const presentedGroups = [
      ...new Set([
        ...sealedPeriodKeys.keys(),
        ...presentedNames(described.accessGroups, "accessGroups"),
        ...presentedByPeriodSource,
      ]),
    ];

    /** @type {Record<string, string[]>} */
    const periodCoordinates = {};
    for (const [accessGroup, family] of sealedPeriodKeys) {
      setOwn(periodCoordinates, accessGroup, [...family.keys()].filter(isPeriodKeyLabel).sort());
    }

    /** @type {Record<string, string[]>} */
    const policyPeriodCoordinates = {};
    for (const accessGroup of Object.keys(periodCoordinates)) {
      setOwn(policyPeriodCoordinates, accessGroup, [...periodCoordinates[accessGroup]]);
    }
    let decision;
    try {
      decision = await this.#accessPolicy.decide(
        claims,
        {
          contentNames: [...presentedContent],
          accessGroups: [...presentedGroups],
          periodCoordinates: policyPeriodCoordinates,
          ...(sourceLabels === undefined ? {} : { sourcePeriodCoordinates }),
        },
        policyInput,
      );
    } catch (cause) {
      if (/** @type {any} */ (cause)?.code === "policy_unavailable") throw cause;
      throw dcaError("internal_error", "the access policy failed unexpectedly");
    }
    if (decision === null || typeof decision !== "object") {
      throw dcaError(
        "bad_policy",
        "the access policy answered with something that is not a decision",
      );
    }

    const grantedContent = names(decision.contentNames, "contentNames");

    // Only coordinates the request presented can be opened.
    const contentNames = presentedContent.filter((name) => grantedContent.includes(name));

    // Ordinary grants union their exact labels. An independent grant is one
    // trusted authorization decision per family, not an unsigned desired set.
    /** @type {Map<string, PolicyPeriodGrant>} */
    const grantByGroup = new Map();
    for (const grant of periodGrants(decision.periodGrants)) {
      if (!presentedGroups.includes(grant.accessGroup)) continue;
      const prior = grantByGroup.get(grant.accessGroup);
      if (
        prior !== undefined &&
        (grant.authorizePeriod !== undefined || prior.authorizePeriod !== undefined)
      ) {
        throw dcaError("bad_policy", "an independent period grant occurs once per family");
      }
      if (grant.authorizePeriod !== undefined) {
        grantByGroup.set(grant.accessGroup, grant);
      } else {
        const requested = new Set(own(periodCoordinates, grant.accessGroup) ?? []);
        const periods = [...new Set(grant.periods ?? [])].filter((t) => requested.has(t)).sort();
        const priorPeriods = prior?.periods ?? [];
        grantByGroup.set(grant.accessGroup, {
          accessGroup: grant.accessGroup,
          periods: [...new Set([...priorPeriods, ...periods])].sort(),
        });
      }
    }
    const grants = [...grantByGroup.values()];
    // Sources see all validated grants at once, so article capacity is reserved
    // across families before optional future output is selected.
    const selectPeriods =
      this.#periodCapabilitySource?.selection(request, invocation, grants) ?? null;
    /** @type {{ accessGroup: string, periods: string[] }[]} */
    const periodKeyGrants = [];
    /** @type {{ accessGroup: string, periodCount: number, route: PeriodRoute }[]} */
    const periodCapabilities = [];
    for (const grant of grants) {
      const { accessGroup } = grant;
      const independent = grant.authorizePeriod !== undefined;
      const grantPeriods = grant.periods ?? [];
      const periodCount = grant.futurePeriodCount ?? grantPeriods.length;
      if (independent && selectPeriods === null) {
        throw dcaError(
          "bad_policy",
          "an independent period grant requires a selected capability source",
        );
      }
      if (independent || periodCount > 0) {
        let route =
          selectPeriods === null
            ? { kind: /** @type {const} */ ("period-keys") }
            : selectionOf(selectPeriods, accessGroup, periodCount, grant);
        if (independent && route.kind === "period-keys") {
          throw dcaError("bad_config", "an independent grant cannot select the base prefix route");
        }
        if (!independent && route.kind === "selected") {
          const authorized = new Set(grantPeriods);
          const selected = route.selected.filter((selection) => authorized.has(selection.t));
          route = selected.length > 0 ? { kind: "selected", selected } : { kind: "period-keys" };
        }
        periodCapabilities.push({
          accessGroup,
          periodCount,
          route,
          ...(independent ? {} : { authorizedPeriods: grantPeriods }),
        });
      }
      if (independent) continue;
      const family = sealedPeriodKeys.get(accessGroup);
      if (family === undefined) continue;
      const allowed = new Set(grant.periods ?? []);
      const grantedLabels = [...family.keys()].filter((t) => allowed.has(t)).sort();
      if (grantedLabels.length > 0) periodKeyGrants.push({ accessGroup, periods: grantedLabels });
    }

    // What has a delivery route, counted before opening-key work. A
    // period this engine can name is counted as itself. A group a source
    // selected a representation of counts the coordinates that selection
    // named, and replaces the period-key prefix of the same group, because the
    // engine delivers the selected representation there. A group with
    // neither has nothing to deliver and counts for nothing. The policy may
    // still have authorized such a group; that is not a policy denial.
    const grantedPeriods = periodCapabilities.reduce((total, { accessGroup, route }) => {
      if (route.kind === "selected") return total + route.selected.length;
      if (
        route.kind === "unavailable" ||
        route.kind === "authorized-unavailable" ||
        route.kind === "denied"
      )
        return total;
      const grant = periodKeyGrants.find((entry) => entry.accessGroup === accessGroup);
      return total + (grant?.periods.length ?? 0);
    }, 0);

    // A family a content-key source presented stays out of the report: the
    // client never sent it in a period section, so its association would read
    // an entry for it as unsolicited and refuse the whole answer.
    /** @type {{ accessGroup: string, reason: 'denied'|'unavailable' }[]} */
    const notDelivered = [];
    for (const accessGroup of new Set([...sealedPeriodKeys.keys(), ...presentedByPeriodSource])) {
      const capability = periodCapabilities.find((entry) => entry.accessGroup === accessGroup);
      if (capability === undefined || capability.route.kind === "denied") {
        notDelivered.push({ accessGroup, reason: "denied" });
      } else if (capability.route.kind === "authorized-unavailable") {
        notDelivered.push({ accessGroup, reason: "unavailable" });
      }
    }

    return {
      contentNames,
      periodKeyGrants,
      periodCapabilities,
      asked: presentedContent.length + presentedGroups.length,
      granted: contentNames.length + grantedPeriods,
      notDelivered,
      policyData: decision.policyData,
      decision,
    };
  }

  /**
   * The opening key this request resolves to inside the authenticated
   * publisher registration, or the retirement that registration answered with.
   *
   * @param {DcaRequest} request
   * @param {PublisherRegistration} publisher
   * @returns {Promise<OpeningKeyState>}
   */
  async #openingKeyState(request, publisher) {
    const issuerName = request.issuerName;
    const keyId = request.keyId;
    let entry;
    try {
      entry =
        typeof issuerName === "string" && typeof keyId === "string"
          ? await publisher.openingKeys.get(issuerName, keyId)
          : undefined;
    } catch {
      // The store is a host collaborator: its throw is this issuer's outage,
      // and its error `code` is not a DCA refusal the request earned.
      throw dcaError("internal_error", "the opening-key store failed unexpectedly");
    }
    if (!entry) {
      throw dcaError("unknown_key", `no key for issuer "${issuerName}" keyId "${keyId}"`);
    }

    // A store gives one of three answers. A keyId it never held is
    // `undefined` above. That request came to the wrong place, has nothing to
    // report per item, and is refused whole. An entry carrying a `privateKey` is a
    // key it holds. `{ retired: true }` is one it held and has let go: the
    // rollover race, where the envelope is intact and the only thing
    // wrong is that the markup outlived the key, so every
    // coordinate the request carried comes back as an error beside a 200.
    //
    // The engine takes the field's presence as the claim and ignores the
    // value behind it. A store
    // that hands over a key which turns out not to open anything has
    // answered the question and been wrong, which the per-item unseal
    // failure reports. An entry claiming both at once, or neither, has not
    // answered it, and reading that as either would let a misconfigured
    // deployment pass for a rollover.
    const retired = /** @type {any} */ (entry).retired === true;
    const claimsKey = Object.hasOwn(entry, "privateKey");
    if (retired === claimsKey) {
      throw dcaError(
        "bad_config",
        `the key store answers for keyId "${keyId}" with an entry that is ` +
          (claimsKey ? "both held and retired" : "neither a private key nor a retirement"),
      );
    }

    if (!retired) {
      // The ordinary procedure is the one a request without `envelope` opens
      // under. An extension name here would let a stripped selector still reach
      // that extension's procedure, which only the allowlist may permit.
      const { algorithm } = /** @type {{ algorithm: unknown }} */ (entry);
      if (typeof algorithm !== "string" || !BASE_ENVELOPE_PROCEDURES.includes(algorithm)) {
        throw dcaError(
          "bad_config",
          `the key store's entry for keyId "${keyId}" registers an algorithm that is not ` +
            `an ordinary envelope procedure (${BASE_ENVELOPE_PROCEDURES.join(", ")})`,
        );
      }
      checkPermittedProcedures(entry, this.#envelopeProcedures, this.#envelopeKeyAlgorithms, keyId);
    }
    return { retired, key: /** @type {any} */ (entry) };
  }

  /**
   * Synchronous pure guard over this engine's captured version set. It
   * performs no publisher lookup, verification, policy or key opening.
   * @param {DcaRequest} request
   * @returns {void}
   */
  checkVersion(request) {
    checkVersion(request, this.#supportedVersions);
  }

  /** @param {number} count */
  #assertPeriodKeyOutput(count) {
    const checked = /** @type {unknown} */ (this.#checkPeriodKeyOutput?.(count));
    if (checked !== undefined) {
      // An accidentally async check cannot authorize output. Consume its
      // rejection so it cannot escape as an unhandled promise afterwards.
      void Promise.resolve(checked).catch(() => {});
      throw dcaError("bad_config", "a period output check returns undefined synchronously");
    }
  }

  /**
   * Two classes of failure, and the return shape carries the split. A
   * request that cannot be trusted at all throws, and the port
   * turns that into a whole-request refusal. A single blob that will not
   * unseal is an entry in `errors` beside the keys that did work - which is
   * the ordinary key-rollover race, not an attack.
   *
   * A refusal on access is a third class: the engine throws `denied` before it
   * looks up the private key, and the port answers 401. The engine refuses only
   * when nothing at all was granted, and under the "complete" not-delivered
   * setting it answers that case with a no-key family report instead when the
   * request presented a reportable family. A request that got part of what it
   * asked for gets a 200 with the rest omitted.
   *
   * The engine puts a retired keyId in the second class rather than the first.
   * This is the one place where the split is a design choice rather than a
   * description. Markup
   * on a CDN outliving a private key is the ordinary end of a rollover, and
   * telling a client its page is malformed would send it looking for a
   * tampering that never happened.
   *
   * @param {DcaRequest} request
   * @param {PublisherRegistration} registration - resolved once by the issuer application
   * @param {IssuerHostPolicyInput} [policyInput] - host members only; the
   *   engine fills the publisher origin in from the verified resource JWT
   * @param {IssuerUnlockInvocation} [invocation] - host-owned context for
   *   this one unlock; period-key-only work may omit it entirely
   * @returns {Promise<UnlockResult>}
   */
  async unlock(request, registration, policyInput = {}, invocation = {}) {
    // A plain document would answer for the fixed fields and carry no
    // coordinates, so it is refused here rather than answered emptily.
    if (!(request instanceof DcaRequest)) {
      throw dcaError(
        "bad_config",
        "IssuerEngine.unlock takes a DcaRequest; parse or construct one first",
      );
    }
    const context = invocationContext(invocation);

    // In the issuer reference's order: a renderId read out of an unverified
    // token anchors nothing, and a key opened before either would be a key
    // opened for whoever asked.
    checkVersion(request, this.#supportedVersions);
    const publisher = publisherFor(request, registration);
    const verified = consumeResourceVerification(
      invocation.verification,
      request,
      publisher.publicKey,
      this.#developmentHttpOrigin,
    );
    const claims =
      verified ?? (await checkEnvelopes(request, publisher.publicKey, this.#developmentHttpOrigin));
    this.checkOperatingIssuerName(request);

    // The engine sets the two reserved fields itself. An opaque context cannot
    // overwrite the authenticated principal or become a second principal.
    const decisionInput = {
      principal: own(policyInput, "principal") ?? null,
      context: own(policyInput, "context"),
      publisher: { origin: claims.resource.origin },
    };
    const granted = await this.#decide(request, claims, decisionInput, context);
    // A presented section source decides its own coordinates after this, so a
    // base denial alone does not refuse the request while one is presented.
    const sources = this.#sectionSources.filter((source) => source.presented(request) === true);

    // A request with no selected delivery route may still have a family its
    // policy authorized. In that case answer with no key, even when the host
    // chooses not to disclose a notDelivered reason. Only an actual complete
    // policy denial may take the Section 6.2 whole-request refusal path.
    // A request that asked for nothing never arrives here
    // through structural admission, which refuses it before this engine
    // runs; the count stays on this branch for a host that reaches the
    // engine directly, where an empty walk is no decision to report.
    const notDelivered = this.#notDeliveredReport === "none" ? [] : granted.notDelivered;
    /** @returns {UnlockResult} */
    const completeDenial = () => {
      const policyAuthorized =
        granted.contentNames.length > 0 ||
        granted.periodCapabilities.some(({ route }) => route.kind !== "denied");
      // Section 6.2 also lets a complete policy denial use a no-key result
      // when the selected report names a presented family. Both no-key
      // outcomes are built from the decision without opening-key lookup
      // when no section source is presented.
      if (
        policyAuthorized ||
        (this.#notDeliveredReport === "complete" && notDelivered.length > 0)
      ) {
        this.#assertPeriodKeyOutput(0);
        return {
          contentKeys: [],
          periodKeys: [],
          capabilities: [],
          errors: [],
          notDelivered,
          policyData: granted.policyData,
        };
      }
      throw dcaError("denied", "nothing this request asked for is granted to this caller");
    };
    if (sources.length === 0 && granted.asked > 0 && granted.granted === 0) return completeDenial();

    /** @type {Promise<{ state: OpeningKeyState, procedure: string|null }>|undefined} */
    let openingContextPromise;
    const openingContext = () => {
      openingContextPromise ??= (async () => {
        const state = await this.#openingKeyState(request, publisher);
        // The anchor half of every binding below, out of the verified token.
        // The application's registration came from the token's exact kid; the
        // request's diagnostic `resource` is not read. A renderId taken from it
        // would be the client's word for which render these blobs belong to.
        const procedure = state.retired
          ? null
          : envelopeProcedureOf(state, request, this.#envelopeProcedures);
        return { state, procedure };
      })();
      return openingContextPromise;
    };

    /** @type {ReturnType<typeof openerAt>|undefined} */
    let openedAt;
    /** @type {(sealed: unknown, coordinate: BoundCoordinate) => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>} */
    const open = async (sealed, coordinate) => {
      if (openedAt === undefined) {
        const { state, procedure } = await openingContext();
        openedAt = openerAt(
          claims.resource.renderId,
          state,
          procedure,
          this.#envelopeProcedures,
          /** @type {string} */ (request.keyId),
        );
      }
      return openedAt(sealed, coordinate);
    };

    /** @type {{ contentName: string, key: string }[]} */
    const contentKeys = [];
    /** @type {{ accessGroup: string, period: string, key: string }[]} */
    const periodKeys = [];
    /** @type {{ kind: string, accessGroup: string, entries: { t: string, key: string }[], interpretation: any }[]} */
    const capabilities = [];
    // One failure per coordinate, kept by coordinate until the end: a later
    // answer for the same coordinate replaces an earlier one, as the map did.
    /** @type {Map<string, { error: string, message: string }>} */
    const errors = new Map();

    // The name a blob is opened at is the same string the policy said yes
    // to. Reading the coordinate off a field beside the blob instead would
    // open a `premium` blob under a `free` grant: the decision would be made
    // on one label and the binding rebuilt from the other, and an attacker
    // who can write the request holds both.
    // A composed source is constructed only after an authorized ordinary seal
    // fails and only while this issuer holds the opening key. A retired keyId
    // ends its reach into the render: a source that can produce material of its
    // own would otherwise answer under a key this issuer has let go of, which
    // is the rollover answered as though it had not happened.
    const grantedContentNames = new Set(granted.contentNames);
    /** @type {Promise<((contentName: string) => Promise<ContentKeyAnswer>)|null>|undefined} */
    let fromSourcePromise;
    const contentKeySource = this.#contentKeySource;
    const fromSourceForFallback = () => {
      if (contentKeySource === null) return Promise.resolve(null);
      fromSourcePromise ??= (async () => {
        const { state } = await openingContext();
        if (state.retired) return null;

        let scope;
        try {
          scope = await this.#contentKeyScope?.(publisher);
        } catch (cause) {
          throw contentKeySourceFault(cause);
        }
        return contentKeysOf(contentKeySource, {
          request,
          decision: granted.decision,
          scope,
          renderId: claims.resource.renderId,
          open: async (sealed, bindingCoordinate, forContentName) => {
            const hasContentName = Object.hasOwn(bindingCoordinate, "contentName");
            const hasAuxiliaryBinding = [
              "accessGroup",
              "t",
              "suppliedT",
              "chainKey",
              "chainsPerDay",
              "periodMinutes",
            ].some((field) => Object.hasOwn(bindingCoordinate, field));
            const bindingName = own(bindingCoordinate, "contentName");
            const name = hasContentName ? bindingName : forContentName;
            if (
              (hasContentName && hasAuxiliaryBinding) ||
              typeof name !== "string" ||
              !grantedContentNames.has(name) ||
              (hasContentName && forContentName !== undefined && forContentName !== bindingName)
            ) {
              throw dcaError(
                "bad_config",
                "a contentKeySource asked to open outside its granted content names",
              );
            }
            // A direct content seal has one normalized BIND coordinate.
            // Auxiliary material keeps its native coordinate; the served
            // content name is authorization context, not another BIND field.
            const coordinate = hasContentName
              ? { contentName: /** @type {string} */ (bindingName) }
              : bindingCoordinate;
            return open(sealed, coordinate);
          },
        });
      })();
      return fromSourcePromise;
    };

    // Only a granted name's envelopes are read.
    const sealedContentKeys = sealedCandidates(
      request.sealedContentKeys,
      SEALED_FIELDS.contentKeys,
      ([contentName]) => grantedContentNames.has(contentName),
    );
    for (const contentName of granted.contentNames) {
      // Every record at this name is a source candidate. Each opens under the
      // one granted coordinate, and every distinct key that opens goes out as
      // a candidate: an envelope that opens does not prove its key opens the
      // content. A name a composed source presented has no record, and opens
      // its absent value once, as before.
      const sources = sealedContentKeys.get(contentName) ?? [undefined];
      /** @type {string[]} */
      const opened = [];
      /** @type {{ error: string, message: string }|null} */
      let failure = null;
      for (const sealed of sources) {
        const answer = await open(sealed, { contentName });
        if ("error" in answer) failure ??= answer.error;
        else distinctPush(opened, base64urlEncode(answer.bytes));
      }

      // Each item gets one answer. A failed content-key seal is provisional while
      // another way to produce the same key is still to be asked, and a
      // source that answers with bytes or an error replaces any earlier error.
      if (opened.length === 0 && failure?.error !== "key_retired") {
        const fromSource = await fromSourceForFallback();
        if (fromSource !== null) {
          const answer = await answerFor(fromSource, contentName);
          if ("bytes" in answer) opened.push(base64urlEncode(answer.bytes));
          else if ("error" in answer) failure = answer.error;
        }
      }

      for (const key of opened) contentKeys.push({ contentName, key });
      if (opened.length === 0) errors.set(contentName, failure ?? UNSEAL_FAILED);
    }

    // A composed source represents the capabilities it already selected,
    // and the period keys of a selected group are not opened beside it:
    // one granted capability reaches a client once. The opener it is handed
    // is confined to the coordinates it named, so the source can reach only
    // the coordinates the engine counted.
    // A retired keyId ends that reach as it does on the content seam. A
    // source is not consulted under a key this issuer has let go of, and a
    // group it selected is answered with the rollover under the group's own
    // label - once, because the selection is one representation of that
    // group.
    const selectedCoordinates = new Set(
      granted.periodCapabilities.flatMap(({ accessGroup, route }) =>
        (route.kind === "selected" ? route.selected : []).map((selection) =>
          selectedCoordinateOf(claims.resource.renderId, accessGroup, selection),
        ),
      ),
    );
    let fromPeriods = null;
    const selectedCapabilities = Object.freeze(
      granted.periodCapabilities.flatMap(({ accessGroup, route }) =>
        route.kind === "selected"
          ? [Object.freeze({ accessGroup, selected: Object.freeze([...route.selected]) })]
          : [],
      ),
    );

    // Only a granted label's envelopes are read.
    const sealedPeriodKeys = sealedCandidates(
      request.sealedPeriodKeys,
      SEALED_FIELDS.periodKeys,
      ([accessGroup, t]) =>
        granted.periodKeyGrants.some(
          (grant) => grant.accessGroup === accessGroup && grant.periods.includes(t),
        ),
    );
    // Reserve actual fallback output before a source clamps optional output.
    // Retain the decision's order within each route kind.
    const orderedCapabilities = [
      ...granted.periodCapabilities.filter(({ route }) => route.kind !== "selected"),
      ...granted.periodCapabilities.filter(({ route }) => route.kind === "selected"),
    ];
    for (const { accessGroup, route } of orderedCapabilities) {
      if (
        route.kind === "unavailable" ||
        route.kind === "authorized-unavailable" ||
        route.kind === "denied"
      )
        continue;

      if (route.kind === "selected" && (await openingContext()).state.retired) {
        for (const { t } of route.selected) {
          errors.set(
            `${accessGroup}${BIND_DELIMITER}${t}`,
            retirementOf(/** @type {string} */ (request.keyId)),
          );
        }
        continue;
      }

      // Each distinct opened key at a label is one candidate there.
      /** @type {{ t: string, key: string }[]} */
      const openedFamily = [];
      /** @param {string} t @param {Uint8Array} bytes */
      const keep = (t, bytes) => {
        const key = base64urlEncode(bytes);
        if (!openedFamily.some((entry) => entry.t === t && entry.key === key))
          openedFamily.push({ t, key });
      };
      /** @type {PeriodCapabilityAnswer|null} */
      let represented = null;

      if (route.kind === "selected") {
        fromPeriods ??= this.#periodCapabilitySource?.capabilities(
          {
            request,
            periodKeyCount: periodKeys.length,
            selectedCapabilities,
            open: openerWithin(open, claims.resource.renderId, selectedCoordinates),
          },
          context,
        );
        if (typeof fromPeriods !== "function") {
          throw dcaError(
            "bad_config",
            "a periodCapabilitySource capabilities(unlock) must return a lookup " +
              "for its selected representation",
          );
        }
        const representation = await representationFor(
          fromPeriods,
          accessGroup,
          route.selected,
          claims.resource.renderId,
        );
        if (representation.kind === "omitted" && !("periods" in representation)) continue;
        represented = /** @type {PeriodCapabilityAnswer} */ (representation);
        const authorizedPeriods = granted.periodCapabilities.find(
          (entry) => entry.accessGroup === accessGroup,
        )?.authorizedPeriods;
        /** @type {Map<string, any>} */
        const failed = new Map();
        for (const period of represented.periods) {
          if (authorizedPeriods && !authorizedPeriods.includes(period.t)) {
            throw dcaError(
              "bad_config",
              `a periodCapabilitySource represented an ungranted period for ${JSON.stringify(accessGroup)}`,
            );
          }
          // A period reports under the label it is delivered at, and
          // a selected coordinate that failed reports under its own.
          if ("bytes" in period) keep(period.t, period.bytes);
          else if (!failed.has(period.t)) failed.set(period.t, period.error);
        }
        // A rival candidate that opened at a label answers it; the failure
        // of another candidate there is no error (core Section 7.1).
        for (const [t, error] of failed) {
          if (!openedFamily.some((entry) => entry.t === t))
            errors.set(`${accessGroup}${BIND_DELIMITER}${t}`, error);
        }
      } else {
        const periods =
          granted.periodKeyGrants.find((grant) => grant.accessGroup === accessGroup)?.periods ?? [];
        const family = sealedPeriodKeys.get(accessGroup);
        for (const t of periods) {
          let openedAny = false;
          /** @type {{ error: string, message: string }|null} */
          let failure = null;
          // One grant, every source record at it: each opens on its own.
          for (const sealed of family?.get(t) ?? [undefined]) {
            const opened = await open(sealed, { accessGroup, t });
            if ("error" in opened) failure ??= opened.error;
            else {
              keep(t, opened.bytes);
              openedAny = true;
            }
          }
          // The format reports a content failure by contentName and a
          // period failure as the pair, under the delimiter the sealer
          // already bans inside both fields.
          if (!openedAny)
            errors.set(`${accessGroup}${BIND_DELIMITER}${t}`, failure ?? UNSEAL_FAILED);
        }
      }

      // A family whose every period failed never gets a record here,
      // because field presence selects the client's cached delivery
      // path.
      if (openedFamily.length > 0) {
        if (
          route.kind === "selected" &&
          /** @type {PeriodCapabilityAnswer} */ (represented).kind !== "period-keys"
        ) {
          capabilities.push({
            kind: /** @type {PeriodCapabilityAnswer} */ (represented).kind,
            accessGroup,
            entries: openedFamily,
            interpretation: /** @type {PeriodCapabilityAnswer} */ (represented).interpretation,
          });
        } else {
          for (const { t, key } of openedFamily) periodKeys.push({ accessGroup, period: t, key });
        }
      }
    }

    // Each presented source answers last, under this request's key state and
    // through its own declared openers only. A throw refuses the whole
    // request: nothing assembled above leaves.
    /** @type {Record<string, unknown>} */
    const sections = {};
    const frozenClaims = frozenCopy(claims.resource);
    const frozenInput = frozenPolicyInput(decisionInput);
    for (const source of sources) {
      const answer = await source.respond(
        Object.freeze({
          request,
          claims: frozenClaims,
          policyInput: frozenInput,
          invocation: context,
          openAuxiliary: auxiliaryOpenerAt(
            openingContext,
            /** @type {string} */ (request.keyId),
            source.envelopeOpeners,
          ),
        }),
      );
      if (answer === null || typeof answer !== "object" || Array.isArray(answer)) {
        throw dcaError("bad_config", `the section source ${source.name} answers an object`);
      }
      for (const [member, value] of Object.entries(answer)) {
        if (!source.members.includes(member)) {
          throw dcaError(
            "bad_config",
            `the section source ${source.name} wrote ${member}, which it did not declare`,
          );
        }
        if (Object.hasOwn(sections, member)) {
          if (!periodGeometriesAgree(sections[member], value)) {
            throw dcaError("bad_config", `two section sources wrote different ${member}`);
          }
          continue;
        }
        setOwn(sections, member, value);
      }
    }
    if (sources.length > 0 && granted.granted === 0 && Object.keys(sections).length === 0) {
      return completeDenial();
    }

    // A coordinate where some candidate produced a key reports no error,
    // even when a rival record there failed.
    for (const { contentName } of contentKeys) errors.delete(contentName);
    for (const { accessGroup, period } of periodKeys)
      errors.delete(`${accessGroup}${BIND_DELIMITER}${period}`);

    // A source's output constraint covers the complete response, including
    // ordinary fallback families and requests with no selected coordinates.
    // Capture the check at composition; only a count crosses this boundary.
    this.#assertPeriodKeyOutput(periodKeys.length);

    return {
      contentKeys,
      periodKeys,
      capabilities,
      errors: [...errors].map(([coordinate, failure]) => ({ coordinate, ...failure })),
      notDelivered,
      policyData: granted.policyData,
      ...(Object.keys(sections).length > 0 ? { sections } : {}),
    };
  }
}

/**
 * A held entry's `envelopes` allowlist, checked where the engine reads the
 * entry: this is the trusted configuration, so an allowlist the engine cannot
 * honour is the issuer's fault on every request, never a per-item refusal the
 * client would read as a bad blob. Each name is the key's own ordinary
 * procedure or an extension procedure this engine holds an opener for. The
 * other base procedure belongs to another key type, and so does an extension
 * procedure that declares key algorithms other than the entry's. An extension
 * procedure without a declaration checks the key itself when it runs.
 *
 * @param {object} entry
 * @param {Readonly<Record<string, EnvelopeProcedure>>} procedures
 * @param {Readonly<Record<string, readonly string[]>>} keyAlgorithms - by procedure, when declared
 * @param {unknown} keyId
 */
function checkPermittedProcedures(entry, procedures, keyAlgorithms, keyId) {
  if (!Object.hasOwn(entry, "envelopes")) return;
  const { algorithm, envelopes } = /** @type {{ algorithm: unknown, envelopes: unknown }} */ (
    entry
  );
  const usable = (/** @type {unknown} */ name) =>
    name === algorithm ||
    (typeof name === "string" &&
      Object.hasOwn(procedures, name) &&
      (!Object.hasOwn(keyAlgorithms, name) ||
        keyAlgorithms[name].includes(/** @type {string} */ (algorithm))));
  if (
    !Array.isArray(envelopes) ||
    envelopes.length === 0 ||
    new Set(envelopes).size !== envelopes.length ||
    !envelopes.every(usable)
  ) {
    throw dcaError(
      "bad_config",
      `the key store's entry for keyId "${keyId}" permits envelope procedures this ` +
        "engine cannot honour: envelopes must list distinct names, each the key's " +
        "algorithm or a procedure this engine was given for that algorithm",
    );
  }
}

/**
 * The envelope procedure every sealed value of this unlock opens under: base
 * keys and section-source envelopes alike. This is the one place an unlock
 * selects a procedure.
 *
 * A request without `envelope` gets the ordinary procedure the trusted key
 * entry registers (`algorithm`), when the entry's `envelopes` permits it. A
 * present `envelope` is the client's unsigned word, so it selects a procedure
 * only when this engine holds an opener under that name and the key entry
 * lists the name in `envelopes`. Every other value, including a base
 * procedure's name, selects nothing: the unlock then opens nothing rather than
 * fall back, because a fallback would let a stripped or altered selector reach
 * a procedure the entry does not permit.
 *
 * @param {OpeningKeyState} state - a held key; callers answer a retirement first
 * @param {DcaRequest} request
 * @param {Readonly<Record<string, EnvelopeProcedure>>} procedures
 * @returns {string|null} the procedure, or null when the selector selects none
 */
function envelopeProcedureOf(state, request, procedures) {
  const selector = request.envelope;
  const permitted = state.key.envelopes;
  if (selector === undefined) {
    const ordinary = state.key.algorithm;
    return permitted === undefined || /** @type {unknown[]} */ (permitted).includes(ordinary)
      ? ordinary
      : null;
  }
  if (
    typeof selector === "string" &&
    Object.hasOwn(procedures, selector) &&
    Array.isArray(permitted) &&
    permitted.includes(selector)
  ) {
    return selector;
  }
  return null;
}

/**
 * @param {unknown} value
 * @returns {{ openers: Readonly<Record<string, EnvelopeProcedure>>,
 *   keyAlgorithms: Readonly<Record<string, readonly string[]>> }}
 */
function checkedEnvelopeProcedures(value) {
  const refuse = () =>
    dcaError(
      "bad_config",
      "envelopeProcedures maps extension procedure names to openers, or to an opener with " +
        "the non-empty list of key algorithms it opens under; base procedures are not replaced",
    );
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw refuse();
  /** @type {Record<string, EnvelopeProcedure>} */
  const openers = {};
  /** @type {Record<string, readonly string[]>} */
  const keyAlgorithms = {};
  for (const [name, procedure] of Object.entries(value)) {
    if (BASE_ENVELOPE_PROCEDURES.includes(name)) throw refuse();
    if (typeof procedure === "function") {
      setOwn(openers, name, procedure);
      continue;
    }
    const { open, keyAlgorithms: declared } = /** @type {any} */ (procedure ?? {});
    if (
      typeof open !== "function" ||
      !Array.isArray(declared) ||
      declared.length === 0 ||
      !declared.every((algorithm) => typeof algorithm === "string")
    ) {
      throw refuse();
    }
    setOwn(openers, name, open);
    setOwn(keyAlgorithms, name, Object.freeze([...declared]));
  }
  return { openers: Object.freeze(openers), keyAlgorithms: Object.freeze(keyAlgorithms) };
}

/**
 * The auxiliary opener a section source is handed. It resolves the request's
 * opening key only after that source has permitted an open, then uses the
 * selected procedure and the source's opener. The source names the AAD its own
 * binding builds; it neither names the procedure nor holds the key.
 *
 * @param {() => Promise<{ state: OpeningKeyState, procedure: string|null }>} openingContext
 * @param {string} keyId - for the retirement message only
 * @param {Readonly<Record<string, (sealed: unknown, privateKey: CryptoKey, aad: Uint8Array) => Promise<Uint8Array>>>} openers
 * @returns {ResponseSectionUnlock['openAuxiliary']}
 */
function auxiliaryOpenerAt(openingContext, keyId, openers) {
  return async (sealed, envelope) => {
    if (
      envelope === null ||
      typeof envelope !== "object" ||
      Object.keys(envelope).some((name) => name !== "aad") ||
      !(envelope.aad instanceof Uint8Array)
    ) {
      throw dcaError(
        "bad_config",
        "a section source opens under AAD bytes alone; the engine selects the envelope procedure",
      );
    }
    const { state, procedure } = await openingContext();
    if (state.retired) return { error: retirementOf(keyId) };
    // The source's payload has no form under this key's procedure, so nothing
    // it presents was sealed to this key.
    if (procedure === null || !Object.hasOwn(openers, procedure)) return { error: UNSEAL_FAILED };
    try {
      const bytes = await openers[procedure](
        sealed,
        state.key.privateKey,
        Uint8Array.from(envelope.aad),
      );
      if (!(bytes instanceof Uint8Array)) return { error: UNSEAL_FAILED };
      return { bytes: Uint8Array.from(bytes) };
    } catch (cause) {
      if (cause instanceof DcaError && cause.code === "bad_config") throw cause;
      // An envelope that does not open under this key and AAD is malformed,
      // moved or altered; no case is told apart from another.
      return { error: UNSEAL_FAILED };
    }
  };
}

/**
 * The one opening operation of an unlock, closed over the verified render and
 * the key state this request resolved to. The binding is rebuilt from that
 * renderId and the coordinate the value is presented at, and the renderId is
 * written last, so a coordinate that named one of its own moves nothing. A
 * caller gets bytes or a typed failure and never the key that produced them.
 *
 * Every canonical sealed-key envelope carries a 16-byte key. An envelope of
 * another width does not open, and the coordinate is answered with the refusal
 * every unopenable value gets.
 *
 * @param {string} renderId - out of the verified token
 * @param {OpeningKeyState} state
 * @param {string|null} procedure - `envelopeProcedureOf`'s choice; null opens nothing
 * @param {Readonly<Record<string, EnvelopeProcedure>>} procedures - extension procedures
 * @param {string} keyId - for the retirement message only
 * @returns {(sealed: unknown, coordinate: BoundCoordinate)
 *   => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>}
 */
function openerAt(renderId, state, procedure, procedures, keyId) {
  return async (sealed, coordinate) => {
    if (state.retired) return { error: retirementOf(keyId) };
    if (typeof sealed !== "string" || procedure === null) return { error: UNSEAL_FAILED };
    try {
      const binding = /** @type {any} */ ({ ...coordinate, renderId });
      if (Object.hasOwn(procedures, procedure)) {
        // An extension procedure gets the BIND octets base keySealing would
        // use as AAD, built from the same verified coordinate.
        const aad = utf8Encode(bindValue(binding));
        const bytes = await procedures[procedure](
          sealed,
          Object.freeze({ privateKey: state.key.privateKey, publicKey: state.key.publicKey }),
          aad,
        );
        if (!(bytes instanceof Uint8Array) || bytes.length !== 16) return { error: UNSEAL_FAILED };
        return { bytes: Uint8Array.from(bytes) };
      }
      return { bytes: await unseal(sealed, state.key.privateKey, procedure, { binding }) };
    } catch (cause) {
      // Sealed material that will not open is what the client is told,
      // at the coordinate it presented: the blob is malformed, moved,
      // altered or sealed to a key this issuer does not hold, and none of
      // those is distinguishable from another. Everything else is this
      // issuer's own: an opening key that is not the type it was
      // configured as, an option this build does not carry, a coordinate
      // it could not construct. Those propagate to the whole-request
      // path, which answers them as it answers every other issuer fault.
      if (cause instanceof DcaError && cause.code === "unseal_failed")
        return { error: UNSEAL_FAILED };
      throw cause;
    }
  };
}

/**
 * The opener a period-capability source is handed: this unlock's own, confined
 * to the coordinates that source selected. The engine counted the grant from
 * that selection and skipped the period-key route for it, so a source asking under
 * a coordinate outside it is a composition fault rather than an opening. The
 * base opener still builds the binding, and the source still never sees a key.
 *
 * @param {(sealed: unknown, coordinate: BoundCoordinate)
 *   => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>} open
 * @param {string} renderId - the anchor every coordinate below is bound under
 * @param {Set<string>} selectedCoordinates - BIND values, as selected
 * @returns {(sealed: unknown, coordinate: BoundCoordinate)
 *   => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>}
 */
function openerWithin(open, renderId, selectedCoordinates) {
  return async (sealed, coordinate) => {
    const asked = periodCoordinateValue(renderId, coordinate);
    if (asked === null || !selectedCoordinates.has(asked)) {
      const asAny = /** @type {any} */ (coordinate);
      const at = `${asAny?.accessGroup}${BIND_DELIMITER}${asAny?.suppliedT ?? asAny?.t}`;
      const kind = asAny?.chainKey === true ? "chain" : "period";
      throw dcaError(
        "bad_config",
        `a periodCapabilitySource asked to open the ${kind} key at ${JSON.stringify(at)}, ` +
          "which it did not select",
      );
    }
    return open(sealed, coordinate);
  };
}

/**
 * One coordinate a source selected, as the value a blob at it is bound to. The
 * grant was counted from the group and the t; the binding kind comes off the
 * selection, because a source that selected a chain key selected that
 * key and not the period key standing at the same group and t.
 *
 * A selection names its label `t` under either kind, which is the shape this
 * engine reads a selection in. The binding grammar names a chain position
 * `suppliedT`, so the label moves into that field here, at the one place a
 * selection becomes a coordinate.
 *
 * @param {string} renderId
 * @param {string} accessGroup
 * @param {any} selection
 * @returns {string}
 */
function selectedCoordinateOf(renderId, accessGroup, selection) {
  const value = periodCoordinateValue(renderId, selectionCoordinate(accessGroup, selection));
  if (value === null) {
    throw dcaError(
      "bad_config",
      `a periodCapabilitySource selected a coordinate of ${JSON.stringify(accessGroup)} ` +
        "that names no sealed key of this render",
    );
  }
  return value;
}

/**
 * One selection as the coordinate it names, with its label under the field its
 * binding kind gives it: `t` for a period key, `suppliedT` for a chain
 * position.
 *
 * @param {string} accessGroup
 * @param {any} selection
 * @returns {any}
 */
function selectionCoordinate(accessGroup, selection) {
  const { t, ...rest } = selection ?? {};
  const labelled = selection?.chainKey === true ? { ...rest, suppliedT: t } : { ...rest, t };
  return { ...labelled, accessGroup };
}

/**
 * Whether a represented label names a period coordinate of the kind the result
 * files it as. A `period-keys` answer files its labels into the period-key
 * section and its errors as period-key coordinates, so each label is a
 * period-key label that binds as one. Another representation files its
 * labels in the kind its source selected for the group, so each label binds
 * under the kind and geometry of one of those selections. The grammars are the
 * ones `periodLabels.js` and `bind.js` already own.
 *
 * @param {string} renderId
 * @param {string} accessGroup
 * @param {string} kind - the representation kind the source answered
 * @param {PeriodSelection[]} selected
 * @param {string} t
 * @returns {boolean}
 */
function isRepresentedLabel(renderId, accessGroup, kind, selected, t) {
  if (kind === "period-keys") {
    return isPeriodKeyLabel(t) && periodCoordinateValue(renderId, { accessGroup, t }) !== null;
  }
  return selected.some(
    (selection) =>
      periodCoordinateValue(renderId, selectionCoordinate(accessGroup, { ...selection, t })) !==
      null,
  );
}

/**
 * The complete coordinate an accessGroup, a period label and a binding kind
 * name, in the grammar `bind.js` owns. Null where they name none, which is a
 * source asking under something that is no period coordinate at all.
 *
 * The kind is read off the coordinate rather than assumed, because
 * `accessGroup|t` alone names two blobs: the periodKey and the chain
 * key sealed at the same group and t. The label is passed under the field the
 * coordinate named it in, so a chain coordinate naming the period-key field
 * is refused by the grammar rather than bound as the coordinate beside it.
 *
 * @param {string} renderId
 * @param {any} coordinate
 * @returns {string|null}
 */
function periodCoordinateValue(renderId, coordinate) {
  const { accessGroup, t, suppliedT, chainKey, chainsPerDay, periodMinutes } = coordinate ?? {};
  try {
    return bindValue({
      renderId,
      accessGroup,
      ...(t === undefined ? {} : { t }),
      ...(suppliedT === undefined ? {} : { suppliedT }),
      ...(chainKey === undefined ? {} : { chainKey }),
      ...(chainsPerDay === undefined ? {} : { chainsPerDay }),
      ...(periodMinutes === undefined ? {} : { periodMinutes }),
    });
  } catch {
    return null;
  }
}

/**
 * The rollover, in the one wording every coordinate of a retired keyId gets:
 * the envelope is intact and the key the render was sealed to is gone.
 *
 * @param {string} keyId
 * @returns {{ error: string, message: string }}
 */
function retirementOf(keyId) {
  return {
    error: "key_retired",
    message: `keyId "${keyId}" is retired and this issuer no longer holds it`,
  };
}

/**
 * Coordinates a source says the request presents. A source that answers with
 * anything else is a composition fault and not a policy answer, so it is
 * refused here rather than read as an empty list.
 *
 * @param {any} value
 * @param {string} field
 * @returns {string[]}
 */
function presentedNames(value, field) {
  if (value === undefined) return [];
  if (
    !Array.isArray(value) ||
    value.some((name) => !(field === "contentNames" ? isContentName(name) : isAccessGroup(name)))
  ) {
    throw dcaError("bad_config", `a source presented a ${field} that is not a list of names`);
  }
  return value;
}

/**
 * A typed failure, in the shape every per-item error on the wire has. A source
 * answering with half of one has not said what the client is to be told, so it
 * is refused here rather than filed as an error object of some other shape.
 *
 * @param {any} value
 * @returns {boolean}
 */
function isFailure(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof value.error === "string" &&
    typeof value.message === "string"
  );
}

/**
 * How many of the named members an answer carries. The alternatives a source
 * answers with are exclusive: bytes and an error at once, or a miss beside
 * either, name two answers where one item has one, and reading the first
 * recognized member would pick between them silently.
 *
 * @param {any} answer
 * @param {string[]} members
 * @returns {number}
 */
function membersOf(answer, members) {
  return members.filter((name) => name in answer).length;
}

/**
 * One content key out of a composed source, checked against the three shapes an
 * answer has. Bytes, a miss, or the one failure this item reports, and exactly
 * one of them: anything else is a composition fault, and reading it as a key
 * would file whatever a source handed back. Bytes of another width than v1's
 * content key are the same fault, refused before they are encoded or filed.
 *
 * @param {(contentName: string) => Promise<ContentKeyAnswer>} lookup
 * @param {string} contentName
 * @returns {Promise<ContentKeyAnswer>}
 */
async function answerFor(lookup, contentName) {
  let answer;
  try {
    answer = await lookup(contentName);
  } catch (cause) {
    throw contentKeySourceFault(cause);
  }
  if (
    answer !== null &&
    typeof answer === "object" &&
    membersOf(answer, ["bytes", "miss", "error"]) === 1
  ) {
    const bytes = /** @type {any} */ (answer).bytes;
    if (bytes instanceof Uint8Array) {
      if (bytes.length === CONTENT_KEY_BYTES) return answer;
      throw dcaError(
        "bad_config",
        `a contentKeySource answered ${JSON.stringify(contentName)} with a content key of ` +
          `${bytes.length} bytes; content keys are ${CONTENT_KEY_BYTES} bytes`,
      );
    }
    if (/** @type {any} */ (answer).miss === true) return answer;
    if (isFailure(/** @type {any} */ (answer).error)) return answer;
  }
  throw dcaError(
    "bad_config",
    `a contentKeySource answered ${JSON.stringify(contentName)} with something ` +
      "that is not a content key, a miss or an error",
  );
}

/**
 * What a throw out of a composed content-key source becomes at this engine's
 * boundary. An issuer fault keeps its code, and so does a fault the engine's own
 * opener raised under the source. Anything else is an unexpected fault of
 * trusted issuer code, answered as the access policy's are: a source that
 * throws `denied` would otherwise refuse the whole request as a denial the
 * policy never made.
 *
 * @param {unknown} cause
 * @returns {unknown}
 */
function contentKeySourceFault(cause) {
  if (cause instanceof DcaError && SOURCE_FAULT_CODES.includes(cause.code)) return cause;
  return dcaError("internal_error", "a contentKeySource failed unexpectedly");
}

/**
 * Append `value` unless the list already holds it: identical candidates are
 * one candidate.
 *
 * @param {string[]} list
 * @param {string} value
 */
function distinctPush(list, value) {
  if (!list.includes(value)) list.push(value);
}

/**
 * A composed source's lookup for one unlock, with a throw classified at this
 * engine's boundary.
 *
 * @param {ContentKeySource} source
 * @param {ContentKeyUnlock} unlock
 * @returns {(contentName: string) => Promise<ContentKeyAnswer>}
 */
function contentKeysOf(source, unlock) {
  try {
    return source.contentKeys(unlock);
  } catch (cause) {
    throw contentKeySourceFault(cause);
  }
}

/**
 * What a source will represent of one granted capability, read before any
 * opening key is looked up. A selection names at least one coordinate; a miss
 * leaves the group to the period-key route; unavailable leaves the group with no
 * period output route. Only the explicit `unavailable` selection signal
 * can become the core availability report; every other unavailable selection
 * remains a silent omission. The three are exclusive, and an empty selection
 * is none of them.
 *
 * @param {(accessGroup: string, periodCount: number, grant?: PolicyPeriodGrant) => PeriodSelectionAnswer} lookup
 * @param {string} accessGroup
 * @param {number} periodCount
 * @param {PolicyPeriodGrant} grant
 * @returns {PeriodRoute}
 */
function selectionOf(lookup, accessGroup, periodCount, grant) {
  const answer = lookup(accessGroup, periodCount, grant);
  if (
    answer !== null &&
    typeof answer === "object" &&
    membersOf(answer, ["selected", "miss", "unavailable"]) === 1
  ) {
    if (/** @type {any} */ (answer).miss === true) return { kind: "period-keys" };
    if (/** @type {any} */ (answer).unavailable === true) return { kind: "unavailable" };
    if (/** @type {any} */ (answer).unavailable === "denied") return { kind: "denied" };
    if (/** @type {any} */ (answer).unavailable === "unavailable") {
      return { kind: "authorized-unavailable" };
    }
    const selected = /** @type {any} */ (answer).selected;
    if (
      Array.isArray(selected) &&
      selected.length > 0 &&
      selected.every(
        (entry) => entry !== null && typeof entry === "object" && isPeriodKeyLabel(entry.t),
      )
    ) {
      return { kind: "selected", selected };
    }
  }
  throw dcaError(
    "bad_config",
    `a periodCapabilitySource selected ${JSON.stringify(accessGroup)} with something ` +
      "that is not the coordinates it will represent, a miss or an unavailable representation",
  );
}

/**
 * One selected capability out of a composed source. A represented answer
 * names at least one period, each a label with either bytes or the failure
 * that label reports and never both. There is no
 * miss or empty period list: a selected group reports a key or the reason
 * there is none. The explicit `{ kind: "omitted" }` result alone may omit
 * optional output after capacity clamping; mandatory output must fit or refuse
 * the exchange. Every other answer is a composition fault, refused before filing.
 *
 * A source representing the ordinary period-key section represents this
 * route's period-key profile: a period key of another width is a composition fault, refused here
 * before a byte of it is encoded or filed.
 *
 * Every label becomes a coordinate in `keys` or `errors`, so each one must name
 * a period coordinate of the kind it is filed as. Successful rivals may share
 * a label; a coordinate filed both as a key and as an error, or as repeated
 * failures, is refused before anything is filed.
 *
 * @param {(accessGroup: string, selected: PeriodSelection[]) => Promise<PeriodCapabilityAnswer|{ kind: "omitted" }>} lookup
 * @param {string} accessGroup
 * @param {PeriodSelection[]} selected
 * @param {string} renderId - the anchor every represented coordinate binds under
 * @returns {Promise<PeriodCapabilityAnswer|{ kind: "omitted" }>}
 */
async function representationFor(lookup, accessGroup, selected, renderId) {
  const answer = await lookup(accessGroup, selected);
  if (answer?.kind === "omitted" && Object.keys(answer).length === 1) return answer;
  if (
    answer !== null &&
    typeof answer === "object" &&
    typeof (/** @type {any} */ (answer).kind) === "string" &&
    /** @type {any} */ (answer).kind.length > 0 &&
    Object.hasOwn(/** @type {any} */ (answer), "interpretation") &&
    Array.isArray(/** @type {any} */ (answer).periods) &&
    /** @type {any} */ (answer).periods.length > 0 &&
    /** @type {any} */ (answer).periods.every(
      (/** @type {any} */ period) =>
        period !== null &&
        typeof period === "object" &&
        typeof period.t === "string" &&
        membersOf(period, ["bytes", "error"]) === 1 &&
        (period.bytes instanceof Uint8Array || isFailure(period.error)),
    )
  ) {
    if (/** @type {any} */ (answer).kind === "period-keys") {
      for (const period of /** @type {any} */ (answer).periods) {
        if ("bytes" in period && period.bytes.length !== 16) {
          throw dcaError(
            "bad_config",
            `a periodCapabilitySource represented ${JSON.stringify(accessGroup)} at ` +
              `${JSON.stringify(period.t)} with a period key of ${period.bytes.length} bytes; ` +
              "period keys are 16 bytes",
          );
        }
      }
    }
    const kind = /** @type {any} */ (answer).kind;
    const filed = new Map();
    for (const period of /** @type {any} */ (answer).periods) {
      const { t } = period;
      const successful = "bytes" in period;
      // Several successful keys are rival candidates at one coordinate.
      // A source still cannot report that coordinate both as a key and as
      // an error, or report its failure twice.
      if (filed.has(t) && (!successful || !filed.get(t))) {
        throw dcaError(
          "bad_config",
          `a periodCapabilitySource represented ${JSON.stringify(accessGroup)} at ` +
            `${JSON.stringify(t)} twice`,
        );
      }
      if (!isRepresentedLabel(renderId, accessGroup, kind, selected, t)) {
        throw dcaError(
          "bad_config",
          `a periodCapabilitySource represented ${JSON.stringify(accessGroup)} at ` +
            `${JSON.stringify(t)}, which names no ${JSON.stringify(kind)} coordinate of this render`,
        );
      }
      filed.set(t, successful);
    }
    return answer;
  }
  throw dcaError(
    "bad_config",
    `a periodCapabilitySource represented ${JSON.stringify(accessGroup)} with something ` +
      "that is not the periods it selected",
  );
}

/**
 * A decision's name list, refused rather than coerced. A policy that answers
 * with a string where a list belongs has said something the engine cannot
 * read, and reading it loosely would turn a typo into a grant.
 *
 * @param {any} value
 * @param {string} field - for the message only
 * @returns {string[]}
 */
function names(value, field) {
  if (value === undefined) return [];
  if (
    !Array.isArray(value) ||
    value.some((name) => !(field === "contentNames" ? isContentName(name) : isAccessGroup(name)))
  ) {
    throw dcaError(
      "bad_policy",
      `the access policy answered with a ${field} that is not a list of names`,
    );
  }
  return value;
}

/**
 * A decision's period grants, refused rather than coerced. Ordinary grants
 * name exact labels; independent capability grants use their separate trusted
 * horizon and callback form.
 *
 * @param {any} value
 * @returns {PolicyPeriodGrant[]}
 */
function periodGrants(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw dcaError("bad_policy", "the access policy answered with periodGrants that is not a list");
  }
  return value.map((grant) => {
    if (grant === null || typeof grant !== "object" || Array.isArray(grant)) {
      throw dcaError(
        "bad_policy",
        "a periodGrant is an object with an accessGroup and explicit period labels, or an independent capability grant",
      );
    }
    const accessGroup = own(grant, "accessGroup");
    if (!isAccessGroup(accessGroup)) {
      throw dcaError("bad_policy", "a periodGrant names the accessGroup it opens");
    }
    const independent =
      Object.hasOwn(grant, "futurePeriodCount") || Object.hasOwn(grant, "authorizePeriod");
    if (independent) {
      const futurePeriodCount = own(grant, "futurePeriodCount");
      const authorizePeriod = own(grant, "authorizePeriod");
      if (
        Object.hasOwn(grant, "periodCount") ||
        Object.hasOwn(grant, "periods") ||
        !Number.isSafeInteger(futurePeriodCount) ||
        futurePeriodCount < 0 ||
        typeof authorizePeriod !== "function"
      ) {
        throw dcaError(
          "bad_policy",
          "an independent period grant needs a non-negative futurePeriodCount and trusted authorizePeriod, with no ordinary periods",
        );
      }
      return { accessGroup, futurePeriodCount, authorizePeriod };
    }
    const periods = own(grant, "periods");
    if (
      Object.hasOwn(grant, "periodCount") ||
      !Array.isArray(periods) ||
      periods.some((t) => !isPeriodKeyLabel(t))
    ) {
      throw dcaError("bad_policy", "an ordinary periodGrant names a list of period labels");
    }
    return { accessGroup, periods: [...new Set(periods)] };
  });
}
