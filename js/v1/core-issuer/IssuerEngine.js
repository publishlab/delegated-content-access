// @ts-check
//
// The port is built on this core. It takes an unlock request, unseals what it was
// sent, and returns keys and per-item errors. It knows nothing about HTTP and
// is callable directly as a library.
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
// opening-key state once. Open the granted direct and exact-period values.
// Assemble keys, per-item errors and `policyData`.
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
// asked for is one refusal, and the port answers 401. Denying some of them is a
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
// This engine answers exact coordinates: one presented sealed value per granted
// direct or exact-period coordinate. It reads no clock, because nothing it does
// is selected by an instant. An optional issuer behavior selected by an instant
// receives one host-captured epoch value in its per-unlock invocation context;
// the engine neither samples nor stores it.
//
// The engine accepts two composition seams, one per domain question. Both are
// narrow on purpose. A deployment may inject a `contentKeySource`: another way
// to produce one already-granted content key, asked per granted content name
// after the direct seal has been tried and only while this issuer holds the
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
// exact prefix, counts as something this deployment can answer, and the
// complete denial is counted from that. Then, once the opening-key state is
// resolved, the source represents what it selected and nothing else, under an
// opener confined to those same coordinates. Installing a source therefore
// changes neither the denial nor the reach into the opening keys.
//
// Across both seams, this engine keeps the access decision, and only the one
// opener reaches the opening key. The source's own request members, policy members,
// candidate order and geometry stay in the code that defines them. This engine
// names none of them.

import { base64urlEncode } from "../core-shared/codec.js";
import { open as unseal } from "../core-shared--publisher-issuer/keySealing.js";
import { admitHeader, verify as verifyJwt } from "../core-shared--publisher-issuer/jwt.js";
import {
  BIND_DELIMITER,
  bindValue,
  validateRenderId,
} from "../core-shared--publisher-issuer/bind.js";
import { signableOrigin } from "../core-shared/publisherOrigin.js";
import { DcaError, dcaError } from "../core-shared/errors.js";
import { own, setOwn } from "../core-shared/wire.js";
import { DcaRequest } from "../core-shared--client-issuer/DcaRequest.js";

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
  "accessPolicy",
  "developmentHttpOrigin",
  "contentKeySource",
  "contentKeyScope",
  "periodCapabilitySource",
]);

/** What an item that will not open reports, whichever coordinate carried it. */
const UNSEAL_FAILED = Object.freeze({
  error: "unseal_failed",
  message: "sealed value could not be opened",
});
const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;

/**
 * The verified claims of one request: the resource the publisher signed.
 *
 * @typedef {object} VerifiedClaims
 * @property {any} resource - the resourceJWT payload
 */

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
    throw dcaError("bad_version", `unsupported version ${JSON.stringify(version)}`);
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
  if (
    registration === null ||
    typeof registration !== "object" ||
    registration.kid !== kid ||
    !registration.publicKey ||
    typeof registration.openingKeys?.get !== "function"
  ) {
    throw dcaError(
      "unknown_publisher_key",
      `no publisher registration for kid ${JSON.stringify(kid)}`,
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
  if (typeof resourceId !== "string" || resourceId.length === 0) {
    throw dcaError("bad_jwt", "the signed resource carries no resourceId to decide on");
  }

  const data = own(resource, "data");
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw dcaError("bad_jwt", "the signed resource carries no data object to decide on");
  }

  return { resource };
}

/**
 * @typedef {object} UnlockResult
 * @property {Record<string, string>} contentKeys - base64url raw key bytes, per contentName
 * @property {Record<string, Record<string, string>>} periodKeys - base64url raw key bytes, per accessGroup per t
 * @property {{ kind: string, accessGroup: string, entries: Record<string, string>, interpretation: any }[]} capabilities -
 *   represented period capabilities. The engine preserves the source-declared
 *   kind and interpretation; the processor's configured encoder names the wire
 *   section.
 * @property {Record<string, { error: string, message: string }>} errors
 * @property {any} policyData - opaque host data from the access policy
 */

/**
 * @typedef {object} PolicyPeriodGrant
 * @property {string} accessGroup
 * @property {number} periodCount - an explicit prefix length over the group's
 *   presented `t` labels, in canonical lexicographic order
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
 * @property {{ origin: string }} publisher - the verified signed delivery origin from the
 *   resource JWT; matching it against the observed HTTP Origin belongs to the browser adapter
 */

/**
 * Who may read what. The caller injects it, because the spec assigns this
 * decision to the issuer. It is duck-typed, so the demo's naive policy plugs
 * into the same seam as a strict one.
 *
 * @typedef {object} AccessPolicy
 * @property {(claims: any, requested: { contentNames: string[], accessGroups: string[] }, input: IssuerPolicyDecisionInput) => (PolicyDecision|Promise<PolicyDecision>)} decide -
 *   answers granted `contentNames` and `periodGrants`, a list of
 *   `{ accessGroup, periodCount }` the engine maps to a sorted prefix
 */

/**
 * @typedef {{ algorithm: string, privateKey: CryptoKey }|{ retired: true }} IssuerKeyEntry
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
 * @typedef {object} PublisherRegistration
 * @property {string} kid - the exact resourceJWT header kid this registration answers
 * @property {CryptoKey} publicKey - the publisher's resource-signing key
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
 * @typedef {{ retired: boolean, key: { algorithm: string, privateKey: CryptoKey } }} OpeningKeyState
 */

/**
 * What the policy granted, already clamped to what the request presented.
 *
 * @typedef {object} GrantedCoordinates
 * @property {string[]} contentNames
 * @property {{ accessGroup: string, periods: string[] }[]} periodPrefixes
 * @property {{ accessGroup: string, periodCount: number, route: PeriodRoute }[]} periodCapabilities -
 *   the granted period reach per access group and the representation route the
 *   composition selected before opening-key work
 * @property {number} asked - how many coordinate families the request presented
 * @property {number} granted - how many coordinates the decision opened
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
 *   publisher registration. The engine selects it only after authorization and
 *   active opening-key resolution; the source never receives the registration
 *   or its opening-key view.
 * - `renderId` is the verified render anchor, out of the signed resource.
 * - `open` is the one opening operation, closed over that anchor and over the
 *   key state this request resolved to. It returns bytes or a typed failure,
 *   and it is the only way a source reaches the opening key.
 *
 * @typedef {object} ContentKeyUnlock
 * @property {DcaRequest} request
 * @property {any} decision - the whole policy answer
 * @property {any} scope
 * @property {string} renderId
 * @property {(sealed: unknown, coordinate: { contentName: string }|{ accessGroup: string, t: string })
 *   => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>} open
 */

/**
 * Another way to produce one already-granted content key.
 *
 * The engine asks it per granted content name, after the request's own direct
 * seal has been tried and only while this issuer holds the opening key. It
 * never asks about periods, never files a response member of its own, and never
 * widens a grant: `presented` adds coordinates the policy may decide on, and
 * the decision is still the policy's.
 *
 * @typedef {object} ContentKeySource
 * @property {(request: DcaRequest) => { contentNames?: string[], accessGroups?: string[] }} [presented] -
 *   coordinates this request carries that the ordinary reading does not see.
 *   Presenting grants nothing.
 * @property {(unlock: ContentKeyUnlock) => ((contentName: string) => Promise<ContentKeyAnswer>)} contentKeys -
 *   what this source can produce for one unlock, as a lookup by granted content
 *   name
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
 * @property {boolean} [periodChain] - absent or false selects the exact-period
 *   BIND kind; true selects the period-chain BIND kind
 * @property {number} [chainsPerDay] - authenticated chain geometry when the
 *   selected kind is period-chain
 * @property {number} [periodMinutes] - authenticated chain geometry when the
 *   selected kind is period-chain
 */

/**
 * What a source answers when it is asked which of a granted capability it will
 * represent. A selection names at least one coordinate. A miss declines the
 * group and leaves it to this engine's exact route. `unavailable` means the
 * composition is responsible for the group's period representation but has no
 * eligible coordinate, so the exact output route stays closed. The three are exclusive,
 * and only a selection or an independently available exact prefix counts as a
 * grant.
 *
 * @typedef {{ selected: PeriodSelection[] }|{ miss: true }|{ unavailable: true }} PeriodSelectionAnswer
 */

/**
 * The normalized period route for one granted access group.
 *
 * @typedef {{ kind: 'selected', selected: PeriodSelection[] }
 *   | { kind: 'exact' }
 *   | { kind: 'unavailable' }} PeriodRoute
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
 * What one unlock hands a period-capability source. Two members, because a
 * representation of a granted period is derived from the request's own material
 * and nothing else:
 *
 * - `request` carries this source's own grammar.
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
 * @property {(sealed: unknown, coordinate: BoundCoordinate)
 *   => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>} open
 */

/**
 * @typedef {object} IssuerInvocationContext
 * @property {number} [capturedAtMs] - finite host-captured epoch milliseconds;
 *   sources that select time-dependent capabilities receive it but never a
 *   host clock
 */

/**
 * Another representation of one already-granted period capability, in two
 * steps. `selection` runs while the decision is clamped and before any opening
 * key is looked up. It names the coordinates it will represent, declines to
 * the exact route, or permits no output. `capabilities` runs after opening-key
 * state is resolved and represents only those selected coordinates.
 *
 * A represented group is answered by this source alone; its exact leaves are
 * not also opened. Which groups a source selects belongs to the source and its
 * composition, not to a flag this engine reads.
 *
 * @typedef {object} PeriodCapabilitySource
 * @property {(request: DcaRequest, invocation: IssuerInvocationContext) => { accessGroups?: string[] }} [presented] -
 *   access groups this request carries that the ordinary reading does not see.
 *   Presenting grants nothing.
 * @property {(request: DcaRequest, invocation: IssuerInvocationContext) => ((accessGroup: string, periodCount: number)
 *   => PeriodSelectionAnswer)} selection - which coordinates of a granted
 *   capability this source will represent, answered before any opening key
 * @property {(unlock: PeriodCapabilityUnlock, invocation: IssuerInvocationContext) => ((accessGroup: string, selected: PeriodSelection[])
 *   => Promise<PeriodCapabilityAnswer>)} capabilities - what this source
 *   represents for one unlock, as a lookup by granted access group
 */

/**
 * Copy the one host context a source may observe so a source cannot retain or
 * mutate caller-owned state across unlocks. Exact-only engines deliberately do
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
    if (name !== "capturedAtMs") {
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

  /**
   * @param {object} config
   * @param {string[]} [config.supportedVersions] - what this issuer can read
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
   *   one. Absent, this engine answers the direct seals alone.
   * @param {(registration: PublisherRegistration) => any|Promise<any>} [config.contentKeyScope] -
   *   issuer-host selection of one opaque view for a composed content-key
   *   source. It receives the authenticated registration, never request
   *   labels or a raw signing kid, and runs only after active opening-key
   *   resolution.
   * @param {PeriodCapabilitySource} [config.periodCapabilitySource] - another
   *   representation of one already-granted period capability, for a
   *   deployment that composes one. It selects before the opening keys are
   *   read and represents after. Absent, this engine answers the exact period
   *   leaves alone.
   */
  constructor(config = {}) {
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
      accessPolicy,
      developmentHttpOrigin = false,
      contentKeySource,
      contentKeyScope,
      periodCapabilitySource,
    } = config ?? {};
    if (typeof accessPolicy?.decide !== "function") {
      throw dcaError(
        "bad_config",
        "an accessPolicy is an object with a decide(claims, requested, input)",
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

    this.#supportedVersions = [...(supportedVersions ?? SUPPORTED_VERSIONS)];
    this.#accessPolicy = accessPolicy;
    this.#developmentHttpOrigin = developmentHttpOrigin;
    this.#contentKeySource = contentKeySource ?? null;
    this.#contentKeyScope = contentKeyScope ?? null;
    this.#periodCapabilitySource = periodCapabilitySource ?? null;
  }

  /**
   * What the policy allows, out of what the request actually presented. The
   * decision is read here and nowhere else, so a policy answering with
   * something that is not a decision is a server fault rather than a grant.
   *
   * The policy answers a count per family. On the ordinary exact route the
   * engine maps it to a sorted prefix of labels the request actually carried.
   * On a selected route, the period-capability source instead chooses the
   * coordinates and the ceiling. Either route stays bounded by what the request or a
   * source presented, so a policy cannot grant past it.
   *
   * @param {DcaRequest} request
   * @param {any} claims - the verified payload and the publisher it belongs to
   * @param {IssuerPolicyDecisionInput} policyInput - the host members plus the
   *   verified `resourceJWT.origin` this engine filled in
   * @returns {Promise<GrantedCoordinates>}
   */
  async #decide(request, claims, policyInput, invocation) {
    const sealedContentKeys = request.sealedContentKeys ?? {};
    const sealedPeriodKeys = request.sealedPeriodKeys ?? {};

    // A composed content-key source may see coordinates in members of its
    // own that this engine does not read. They join the presented set the
    // decision chooses out of, and nothing else: a coordinate is still
    // opened only where the policy said yes to it.
    const described = this.#contentKeySource?.presented?.(request) ?? {};
    const describedPeriods = this.#periodCapabilitySource?.presented?.(request, invocation) ?? {};
    const presentedByPeriodSource = presentedNames(describedPeriods.accessGroups, "accessGroups");
    const presentedContent = [
      ...new Set([
        ...Object.keys(sealedContentKeys),
        ...presentedNames(described.contentNames, "contentNames"),
      ]),
    ];
    const presentedGroups = [
      ...new Set([
        ...Object.keys(sealedPeriodKeys),
        ...presentedNames(described.accessGroups, "accessGroups"),
        ...presentedByPeriodSource,
      ]),
    ];

    const decision = await this.#accessPolicy.decide(
      claims,
      { contentNames: presentedContent, accessGroups: presentedGroups },
      policyInput,
    );
    if (decision === null || typeof decision !== "object") {
      throw dcaError(
        "bad_policy",
        "the access policy answered with something that is not a decision",
      );
    }

    const grantedContent = names(decision.contentNames, "contentNames");

    // Only coordinates the request presented can be opened.
    const contentNames = presentedContent.filter((name) => grantedContent.includes(name));

    // A family named more than once takes its longest reach; a count on a
    // family the request never presented opens nothing.
    /** @type {Map<string, number>} */
    const countByGroup = new Map();
    for (const grant of periodGrants(decision.periodGrants)) {
      if (!presentedGroups.includes(grant.accessGroup)) continue;
      const prior = countByGroup.get(grant.accessGroup) ?? 0;
      if (grant.periodCount > prior) countByGroup.set(grant.accessGroup, grant.periodCount);
    }

    // A composed source names what it will represent of a granted
    // capability here, where the decision is clamped and before any opening
    // key exists to reach. It is handed the request and the granted count
    // and answers with coordinates or a miss.
    const selectPeriods = this.#periodCapabilitySource?.selection(request, invocation) ?? null;

    // The canonical prefix: the group's presented labels sorted ascending,
    // cut to the granted count. Object-member order is not a portable
    // coordinate, so the engine sorts rather than trusting the wire's order,
    // and a period past the prefix is never opened even though the request
    // carries its blob.
    /** @type {{ accessGroup: string, periods: string[] }[]} */
    const periodPrefixes = [];
    /** @type {{ accessGroup: string, periodCount: number, route: PeriodRoute }[]} */
    const periodCapabilities = [];
    for (const [accessGroup, periodCount] of countByGroup) {
      if (periodCount > 0) {
        const route =
          selectPeriods === null
            ? { kind: /** @type {const} */ ("exact") }
            : selectionOf(selectPeriods, accessGroup, periodCount);
        periodCapabilities.push({ accessGroup, periodCount, route });
      }
      const family = own(sealedPeriodKeys, accessGroup);
      if (family === null || typeof family !== "object") continue;
      const periods = Object.keys(family).sort().slice(0, periodCount);
      if (periods.length > 0) periodPrefixes.push({ accessGroup, periods });
    }

    // What was granted, counted for the complete-denial refusal alone. A
    // period this engine can name is counted as itself. A group a source
    // selected a representation of counts the coordinates that selection
    // named, and replaces the exact prefix of the same group, because the
    // engine delivers the selected representation there. A group with
    // neither has nothing to deliver and counts for nothing: installing a
    // source, or presenting the group through it, does not count as
    // answering it.
    const grantedPeriods = periodCapabilities.reduce((total, { accessGroup, route }) => {
      if (route.kind === "selected") return total + route.selected.length;
      if (route.kind === "unavailable") return total;
      const prefix = periodPrefixes.find((entry) => entry.accessGroup === accessGroup);
      return total + (prefix?.periods.length ?? 0);
    }, 0);

    return {
      contentNames,
      periodPrefixes,
      periodCapabilities,
      asked: presentedContent.length + presentedGroups.length,
      granted: contentNames.length + grantedPeriods,
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
    const entry =
      typeof issuerName === "string" && typeof keyId === "string"
        ? await publisher.openingKeys.get(issuerName, keyId)
        : undefined;
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

    return { retired, key: /** @type {any} */ (entry) };
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
   * when nothing at all was granted. A request that got part of what it asked
   * for gets a 200 with the rest omitted.
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
   * @param {IssuerInvocationContext} [invocation] - host-owned context for
   *   this one unlock; exact-only work may omit it entirely
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
    const claims = await checkEnvelopes(request, publisher.publicKey, this.#developmentHttpOrigin);

    // The engine sets the two reserved fields itself. An opaque context cannot
    // overwrite the authenticated principal or become a second principal.
    const granted = await this.#decide(
      request,
      claims,
      {
        principal: own(policyInput, "principal") ?? null,
        context: own(policyInput, "context"),
        publisher: { origin: claims.resource.origin },
      },
      context,
    );

    // Nothing granted out of something asked for is one refusal for the
    // whole request. A request that asked for nothing never arrives here
    // through structural admission, which refuses it before this engine
    // runs; the count stays on this branch for a host that reaches the
    // engine directly, where an empty walk is no decision to report.
    if (granted.asked > 0 && granted.granted === 0) {
      throw dcaError("denied", "nothing this request asked for is granted to this caller");
    }

    const state = await this.#openingKeyState(request, publisher);

    // The anchor half of every binding below, out of the verified token.
    // The application's registration came from the token's exact kid; the
    // request's diagnostic `resource` is not read. A renderId taken from it
    // would be the client's word for which render these blobs belong to.
    const open = openerAt(claims.resource.renderId, state, /** @type {string} */ (request.keyId));

    /** @type {Record<string, string>} */
    const contentKeys = {};
    /** @type {Record<string, Record<string, string>>} */
    const periodKeys = {};
    /** @type {{ kind: string, accessGroup: string, entries: Record<string, string>, interpretation: any }[]} */
    const capabilities = [];
    /** @type {Record<string, { error: string, message: string }>} */
    const errors = {};

    // The name a blob is opened at is the same string the policy said yes
    // to. Reading the coordinate off a field beside the blob instead would
    // open a `premium` blob under a `free` grant: the decision would be made
    // on one label and the binding rebuilt from the other, and an attacker
    // who can write the request holds both.
    // A composed source is asked after the direct seal and only while this
    // issuer holds the opening key. A retired keyId ends its reach into the
    // render: a source that can produce material of its own would otherwise
    // answer under a key this issuer has let go of, which is the rollover
    // answered as though it had not happened.
    const scope =
      this.#contentKeySource === null || state.retired
        ? undefined
        : await this.#contentKeyScope?.(publisher);
    const fromSource =
      this.#contentKeySource === null || state.retired
        ? null
        : this.#contentKeySource.contentKeys({
            request,
            decision: granted.decision,
            scope,
            renderId: claims.resource.renderId,
            open,
          });

    const sealedContentKeys = request.sealedContentKeys ?? {};
    for (const contentName of granted.contentNames) {
      const opened = await open(own(sealedContentKeys, contentName), { contentName });
      /** @type {Uint8Array|null} */
      let bytes = "error" in opened ? null : opened.bytes;
      /** @type {{ error: string, message: string }|null} */
      let failure = "error" in opened ? opened.error : null;

      // Each item gets one answer. A failed direct seal is provisional while
      // another way to produce the same key is still to be asked, and a
      // source that answers with bytes or an error replaces any earlier error.
      if (bytes === null && fromSource !== null) {
        const answer = await answerFor(fromSource, contentName);
        if ("bytes" in answer) bytes = answer.bytes;
        else if ("error" in answer) failure = answer.error;
      }

      if (bytes !== null) setOwn(contentKeys, contentName, base64urlEncode(bytes));
      else setOwn(errors, contentName, failure ?? UNSEAL_FAILED);
    }

    // A composed source represents the capabilities it already selected,
    // and the exact leaves of a selected group are not opened beside it:
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
    const fromPeriods =
      this.#periodCapabilitySource === null || state.retired || selectedCoordinates.size === 0
        ? null
        : this.#periodCapabilitySource.capabilities(
            {
              request,
              open: openerWithin(open, claims.resource.renderId, selectedCoordinates),
            },
            context,
          );

    const sealedPeriodKeys = request.sealedPeriodKeys ?? {};
    for (const { accessGroup, route } of granted.periodCapabilities) {
      if (route.kind === "unavailable") continue;

      if (route.kind === "selected" && state.retired) {
        for (const { t } of route.selected) {
          setOwn(
            errors,
            `${accessGroup}${BIND_DELIMITER}${t}`,
            retirementOf(/** @type {string} */ (request.keyId)),
          );
        }
        continue;
      }

      /** @type {Record<string, string>} */
      const openedFamily = {};
      let section = periodKeys;
      /** @type {PeriodCapabilityAnswer|null} */
      let represented = null;

      if (route.kind === "selected") {
        if (typeof fromPeriods !== "function") {
          throw dcaError(
            "bad_config",
            "a periodCapabilitySource capabilities(unlock) must return a lookup " +
              "for its selected representation",
          );
        }
        represented = await representationFor(fromPeriods, accessGroup, route.selected);
        for (const period of represented.periods) {
          // A period reports under the label it is delivered at, and
          // a selected coordinate that failed reports under its own.
          if ("bytes" in period) setOwn(openedFamily, period.t, base64urlEncode(period.bytes));
          else setOwn(errors, `${accessGroup}${BIND_DELIMITER}${period.t}`, period.error);
        }
      } else {
        const periods =
          granted.periodPrefixes.find((prefix) => prefix.accessGroup === accessGroup)?.periods ??
          [];
        const family = own(sealedPeriodKeys, accessGroup);
        for (const t of periods) {
          const opened = await open(own(family, t), { accessGroup, t });
          // The format keys `errors` by contentName and says nothing
          // about a periodKey that will not open. A period is a pair,
          // so it is reported as one, under the delimiter the sealer
          // already bans inside both fields.
          if ("error" in opened)
            setOwn(errors, `${accessGroup}${BIND_DELIMITER}${t}`, opened.error);
          else setOwn(openedFamily, t, base64urlEncode(opened.bytes));
        }
      }

      // A family whose every period failed never gets a member here,
      // because field presence selects the client's cached delivery
      // path.
      if (Object.keys(openedFamily).length > 0) {
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
          setOwn(section, accessGroup, openedFamily);
        }
      }
    }

    return { contentKeys, periodKeys, capabilities, errors, policyData: granted.policyData };
  }
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
 * @param {string} keyId - for the retirement message only
 * @returns {(sealed: unknown, coordinate: { contentName: string }|{ accessGroup: string, t: string })
 *   => Promise<{ bytes: Uint8Array }|{ error: { error: string, message: string } }>}
 */
function openerAt(renderId, state, keyId) {
  return async (sealed, coordinate) => {
    if (state.retired) return { error: retirementOf(keyId) };
    if (typeof sealed !== "string") return { error: UNSEAL_FAILED };
    const { key } = state;
    try {
      const options = { binding: /** @type {any} */ ({ ...coordinate, renderId }) };
      return { bytes: await unseal(sealed, key.privateKey, key.algorithm, options) };
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
 * that selection and skipped the exact route for it, so a source asking under
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
      const kind = asAny?.periodChain === true ? "period-chain" : "period";
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
 * selection, because a source that selected a period-chain key selected that
 * key and not the exact leaf standing at the same group and t.
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
  const { t, ...rest } = selection ?? {};
  const labelled = selection?.periodChain === true ? { ...rest, suppliedT: t } : { ...rest, t };
  const value = periodCoordinateValue(renderId, { ...labelled, accessGroup });
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
 * The complete coordinate an accessGroup, a period label and a binding kind
 * name, in the grammar `bind.js` owns. Null where they name none, which is a
 * source asking under something that is no period coordinate at all.
 *
 * The kind is read off the coordinate rather than assumed, because
 * `accessGroup|t` alone names two blobs: the exact periodKey and the period-chain
 * key sealed at the same group and t. The label is passed under the field the
 * coordinate named it in, so a chain coordinate naming the exact-period field
 * is refused by the grammar rather than bound as the coordinate beside it.
 *
 * @param {string} renderId
 * @param {any} coordinate
 * @returns {string|null}
 */
function periodCoordinateValue(renderId, coordinate) {
  const { accessGroup, t, suppliedT, periodChain, chainsPerDay, periodMinutes } = coordinate ?? {};
  try {
    return bindValue({
      renderId,
      accessGroup,
      ...(t === undefined ? {} : { t }),
      ...(suppliedT === undefined ? {} : { suppliedT }),
      ...(periodChain === undefined ? {} : { periodChain }),
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
  if (!Array.isArray(value) || value.some((name) => typeof name !== "string")) {
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
 * would file whatever a source handed back.
 *
 * @param {(contentName: string) => Promise<ContentKeyAnswer>} lookup
 * @param {string} contentName
 * @returns {Promise<ContentKeyAnswer>}
 */
async function answerFor(lookup, contentName) {
  const answer = await lookup(contentName);
  if (
    answer !== null &&
    typeof answer === "object" &&
    membersOf(answer, ["bytes", "miss", "error"]) === 1
  ) {
    if (/** @type {any} */ (answer).bytes instanceof Uint8Array) return answer;
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
 * What a source will represent of one granted capability, read before any
 * opening key is looked up. A selection names at least one coordinate; a miss
 * leaves the group to the exact route; unavailable leaves the group with no
 * period output route. The three are exclusive, and an empty selection is none
 * of them.
 *
 * @param {(accessGroup: string, periodCount: number) => PeriodSelectionAnswer} lookup
 * @param {string} accessGroup
 * @param {number} periodCount
 * @returns {PeriodRoute}
 */
function selectionOf(lookup, accessGroup, periodCount) {
  const answer = lookup(accessGroup, periodCount);
  if (
    answer !== null &&
    typeof answer === "object" &&
    membersOf(answer, ["selected", "miss", "unavailable"]) === 1
  ) {
    if (/** @type {any} */ (answer).miss === true) return { kind: "exact" };
    if (/** @type {any} */ (answer).unavailable === true) return { kind: "unavailable" };
    const selected = /** @type {any} */ (answer).selected;
    if (
      Array.isArray(selected) &&
      selected.length > 0 &&
      selected.every(
        (entry) => entry !== null && typeof entry === "object" && typeof entry.t === "string",
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
 * One selected capability out of a composed source, checked against the one
 * shape an answer has. It names its periods, at least one, each a label with
 * either bytes or the failure that label reports and never both. There is no
 * miss and no empty answer here: the group was counted as granted because this
 * source selected it, so it reports a key or the reason there is none. Anything
 * else is a composition fault, and reading it as a representation would file
 * whatever a source handed back.
 *
 * A source representing the ordinary exact section represents this route's
 * exact profile: a leaf of another width is a composition fault, refused here
 * before a byte of it is encoded or filed.
 *
 * @param {(accessGroup: string, selected: PeriodSelection[]) => Promise<PeriodCapabilityAnswer>} lookup
 * @param {string} accessGroup
 * @param {PeriodSelection[]} selected
 * @returns {Promise<PeriodCapabilityAnswer>}
 */
async function representationFor(lookup, accessGroup, selected) {
  const answer = await lookup(accessGroup, selected);
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
              `${JSON.stringify(period.t)} with a leaf of ${period.bytes.length} bytes; canonical leaves are 16`,
          );
        }
      }
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
  if (!Array.isArray(value) || value.some((name) => typeof name !== "string")) {
    throw dcaError(
      "bad_policy",
      `the access policy answered with a ${field} that is not a list of names`,
    );
  }
  return value;
}

/**
 * A decision's period grants, refused rather than coerced. Each is a family and
 * a whole, non-negative prefix length; a count that is a string, a fraction or a
 * negative is a decision the engine cannot read, and reading it loosely would
 * turn a typo into a grant or a denial.
 *
 * @param {any} value
 * @returns {{ accessGroup: string, periodCount: number }[]}
 */
function periodGrants(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw dcaError("bad_policy", "the access policy answered with periodGrants that is not a list");
  }
  return value.map((grant) => {
    if (grant === null || typeof grant !== "object") {
      throw dcaError(
        "bad_policy",
        "a periodGrant is an object of an accessGroup and a periodCount",
      );
    }
    const accessGroup = own(grant, "accessGroup");
    const periodCount = own(grant, "periodCount");
    if (typeof accessGroup !== "string") {
      throw dcaError("bad_policy", "a periodGrant names the accessGroup it opens");
    }
    if (!Number.isInteger(periodCount) || periodCount < 0) {
      throw dcaError("bad_policy", "a periodGrant opens a whole, non-negative number of periods");
    }
    return { accessGroup, periodCount };
  });
}
