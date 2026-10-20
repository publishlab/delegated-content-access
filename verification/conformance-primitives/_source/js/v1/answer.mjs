// What this runtime answers when it is asked to run one of the contract's seven
// library calls, and nothing about whether the answer is right.
//
// `answerLine` takes the text of one `dca-operation-bridge-v1` batch and returns
// the finished answer: one line of JSON, `{ protocol, results }`, without a
// trailing newline. `faultLine` takes what `answerLine` threw and returns the one
// `bridge: ...` line a fault writes as its diagnostic, also without a newline.
// This module reads nothing and writes nothing: it touches no process object,
// imports no file module and owns no output stream. An entry supplies the batch
// text, writes the answer line or the fault line, and turns a fault into a
// nonzero exit in the way its runtime allows. Both lines are built here so that
// every entry writes the same bytes.
//
// This module holds no expected value, runs no comparison and prints no
// verdict. It never opens the case corpus, and a request carries no expectation
// for it to read. If a bridge can read the answer, nobody has tested it, and if
// a bridge reports its own conclusion, it hands the harness a second opinion to
// reconcile.
//
// Each operation is one call into this runtime's own crypto library, WebCrypto
// through `globalThis.crypto.subtle`: HKDF-SHA-256 with an empty salt, AES-GCM
// under a 16 or a 32 octet key with the tag appended, an ECDH agreement over
// P-256, a public point exported as the uncompressed SEC 1 encoding, and an
// RSA-OAEP decryption under SHA-256. This module decodes a base64url spelling
// with its own decoder: `Buffer`'s decoder plus the canonical rules the contract
// states. Nothing here reimplements a primitive, and this file imports nothing:
// no reference module, no vector, no corpus. `Buffer` is the runtime's global.
//
// A defined refusal is an answer. `invalid_base64url`, `authentication_failed`
// and `unseal_failed` come back as observations, because refusing correctly is
// a behaviour under test. A request this bridge cannot serve at all, an
// unparseable batch, an unknown operation or an input shape outside the
// contract, throws a `BridgeFault` and returns no partial results; the entry
// turns that into a nonzero exit, and the runner reads it as a run nobody could
// complete.
//
// The bridge answers a short carrier and faults on a spelling that does not
// decode. Every open decodes its base64url members first, so a value outside the
// alphabet ends the batch naming the request; a value that decodes and is then
// too short to hold its carrier's tag gets the operation's own refusal. The
// contract writes both rules once, under Encodings.
//
// The bridge checks every shape it reads, and each one is closed. The envelope
// carries `protocol` and `requests`, a request row carries `id`, `op` and `input`,
// and an input carries exactly the members its operation names. A member nobody
// named means the sender speaks a protocol this bridge has not agreed to.
//
// The bridge reads the batch with this runtime's own JSON parser and nothing
// else. There is no token scanner here. `JSON.parse` keeps one spelling of a
// repeated member and says nothing, and this bridge does not go looking: the
// driver writes every batch and never repeats a member, so a bridge guarding
// against one would guard against its own harness.

const { subtle } = globalThis.crypto;

/** The curve and the two algorithms the contract names, once each. */
const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' };
const RSA_OAEP_SHA256 = { name: 'RSA-OAEP', hash: 'SHA-256' };

/** The protocol a batch names and an answer repeats. */
const BATCH_PROTOCOL = 'dca-operation-bridge-v1';

/** HKDF runs with a salt of zero octets, which the contract fixes. */
const EMPTY_SALT = new Uint8Array(0);
const HKDF_MIN_OCTETS = 1;
const HKDF_MAX_OCTETS = 8160;

/** The AES-GCM tag, appended to the ciphertext in one buffer. */
const GCM_TAG_OCTETS = 16;
const GCM_TAG_BITS = 128;
const GCM_NONCE_OCTETS = 12;
const AES_KEY_OCTETS = [16, 32];

/** An uncompressed SEC 1 P-256 point: the octet 0x04 and two 32-octet coordinates. */
const P256_POINT_OCTETS = 65;
/** The agreed x-coordinate at the P-256 field width, which ECDH answers in bits. */
const P256_FIELD_BITS = 256;

/** A batch or a request this bridge cannot serve, which is never a refusal. */
class BridgeFault extends Error {}

/**
 * The answer to one batch as one JSON line without a trailing newline, or a
 * throw when the batch is one this bridge cannot serve. Nothing is returned for
 * part of a batch, so an entry that writes only what this returns never leaves
 * a partial answer.
 */
export async function answerLine(raw) {
    const results = await answerBatch(raw);
    return JSON.stringify({ protocol: BATCH_PROTOCOL, results });
}

/**
 * The diagnostic line for whatever `answerLine` threw, without a trailing
 * newline. A `BridgeFault` message already names the request and what it lacks.
 * Any other error is the runtime failing inside a call, so its name goes first
 * to say which kind of failure it was.
 */
export function faultLine(error) {
    return error instanceof BridgeFault
        ? `bridge: ${error.message}`
        : `bridge: ${error.name}: ${error.message}`;
}

/**
 * The request envelope, read strictly, and one result per request in request
 * order. Order is irrelevant to the runner, which keys results by the (id, op)
 * pair, so request order stays only because it makes a hand-read batch easy to
 * follow.
 */
async function answerBatch(raw) {
    let request;
    try {
        request = JSON.parse(raw);
    } catch (error) {
        throw new BridgeFault(`the batch on stdin is not readable JSON: ${error.message}`);
    }
    if (!isPlainObject(request)) {
        throw new BridgeFault('the batch on stdin is not a JSON object.');
    }
    closedMembers(request, ['protocol', 'requests'], 'the batch');
    if (typeof request.protocol !== 'string' || request.protocol !== BATCH_PROTOCOL) {
        throw new BridgeFault('the batch names a protocol this bridge does not speak.');
    }
    if (!Array.isArray(request.requests)) {
        throw new BridgeFault('the batch carries no requests array.');
    }

    const results = [];
    for (const entry of request.requests) {
        if (!isPlainObject(entry)) {
            throw new BridgeFault('a request entry is not a JSON object.');
        }
        closedMembers(entry, ['id', 'op', 'input'], 'a request entry');
        if (typeof entry.id !== 'string' || entry.id === '') {
            throw new BridgeFault('a request entry carries no id.');
        }
        if (typeof entry.op !== 'string') {
            throw new BridgeFault(`request ${entry.id} carries no op.`);
        }
        if (!isPlainObject(entry.input)) {
            throw new BridgeFault(`request ${entry.id} carries no input object.`);
        }

        results.push({
            id: entry.id,
            op: entry.op,
            observation: await observe(entry.op, entry.input, entry.id),
        });
    }

    return results;
}

/** One observation for one request, or a fault when the operation is outside the seven. */
async function observe(op, input, id) {
    switch (op) {
        case 'decode-base64url':
            return observeDecodeBase64url(input, id);
        case 'hkdf-sha256':
            return observeHkdfSha256(input, id);
        case 'open-aes-gcm':
            return observeOpenAesGcm(input, id);
        case 'seal-aes-gcm':
            return observeSealAesGcm(input, id);
        case 'ecdh-p256':
            return observeEcdhP256(input, id);
        case 'p256-point':
            return observeP256Point(input, id);
        case 'open-rsa-oaep':
            return observeOpenRsaOaep(input, id);
        default:
            throw new BridgeFault(`request ${id} names operation ${op}, which this bridge does not implement.`);
    }
}

/**
 * The strict field spelling: the RFC 4648 section 5 alphabet, no padding, a
 * length that encodes a whole byte count, and zero unused trailing bits.
 * `decodeStrictBase64url` below applies all four; a value failing any one of
 * them gets this operation's single refusal.
 */
function observeDecodeBase64url(input, id) {
    closedMembers(input, ['value'], `the input of request ${id}`);
    const value = requiredString(input, 'value', id);
    const bytes = decodeStrictBase64url(value);
    if (bytes === null) {
        return { refused: 'invalid_base64url' };
    }
    return { bytesHex: Buffer.from(bytes).toString('hex') };
}

/**
 * One HKDF-SHA-256 derivation over the octets the request carries, run through
 * `subtle.deriveBits` under a salt of zero octets. The info octets travel as the
 * request spells them, so a value carrying 0x00 or an octet above 0x7f reaches
 * the derivation unchanged. An `ikm` or `info` outside canonical base64url, and a
 * `length` outside 1 through 8160, are requests this bridge cannot serve.
 */
async function observeHkdfSha256(input, id) {
    closedMembers(input, ['ikmBase64url', 'infoBase64url', 'length'], `the input of request ${id}`);
    const ikm = carrierBytes(input, 'ikmBase64url', id);
    const info = carrierBytes(input, 'infoBase64url', id);
    const length = requiredInteger(input, 'length', id);
    if (length < HKDF_MIN_OCTETS || length > HKDF_MAX_OCTETS) {
        throw new BridgeFault(
            `request ${id} asks for ${length} HKDF octets, and this operation derives `
            + `${HKDF_MIN_OCTETS} through ${HKDF_MAX_OCTETS}.`,
        );
    }

    const key = await importRaw(ikm, 'HKDF', ['deriveBits'], `request ${id} carries ikm this bridge cannot import`);
    const okm = await subtle.deriveBits({
        name: 'HKDF', hash: 'SHA-256', salt: EMPTY_SALT, info,
    }, key, length * 8);
    return { okmBase64url: encodeBase64url(new Uint8Array(okm)) };
}

/**
 * AES-GCM over one `ciphertext || tag` carrier, which is how the wire carries it
 * and how `subtle.decrypt` takes it, so nothing here splits the tag off. The
 * key's width selects AES-128-GCM or AES-256-GCM. An `aad` of zero octets is
 * passed as zero octets.
 */
async function observeOpenAesGcm(input, id) {
    closedMembers(
        input,
        ['keyBase64url', 'nonceBase64url', 'ciphertextBase64url', 'aadBase64url'],
        `the input of request ${id}`,
    );
    const keyBytes = carrierBytes(input, 'keyBase64url', id);
    const nonce = carrierBytes(input, 'nonceBase64url', id);
    const carrier = carrierBytes(input, 'ciphertextBase64url', id);
    const aad = carrierBytes(input, 'aadBase64url', id);
    checkAesWidths(keyBytes, nonce, id);

    // A carrier too short to hold its own tag gets the contract's refusal rather than a
    // fault: nothing downstream of it can produce a plaintext, and a failed tag
    // states exactly that. A spelling that does not decode is the other malformed
    // shape, and `carrierBytes` above has already made it a nonzero exit.
    if (carrier.length < GCM_TAG_OCTETS) {
        return { refused: 'authentication_failed' };
    }

    const key = await importRaw(keyBytes, 'AES-GCM', ['decrypt'], `request ${id} carries a key this bridge cannot import`);
    let plaintext;
    try {
        plaintext = await subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: GCM_TAG_BITS },
            key,
            carrier,
        );
    } catch {
        // A wrong key, a wrong nonce, other additional data and a flipped octet
        // are one answer, because the tag check does not tell them apart.
        // WebCrypto reports a tag that does not verify as a rejection, and this
        // catch reads every rejection as that refusal without checking the
        // error's name: the refusal is a fact about bytes, and the name is one
        // runtime's spelling of it. A runtime that cannot run AES-GCM at all
        // rejects here too, and then the success cases in the same set disagree,
        // so a run still shows it.
        return { refused: 'authentication_failed' };
    }

    return { plaintextBase64url: encodeBase64url(new Uint8Array(plaintext)) };
}

/**
 * The same cipher in the encrypt direction, over the nonce the request pins; the
 * pinned nonce gives a seal one determined answer. `subtle.encrypt` appends the 16-octet tag,
 * so the observation is the whole `ciphertext || tag` buffer. A seal defines no
 * refusal: this bridge exits nonzero on a seal it cannot compute.
 */
async function observeSealAesGcm(input, id) {
    closedMembers(
        input,
        ['keyBase64url', 'nonceBase64url', 'plaintextBase64url', 'aadBase64url'],
        `the input of request ${id}`,
    );
    const keyBytes = carrierBytes(input, 'keyBase64url', id);
    const nonce = carrierBytes(input, 'nonceBase64url', id);
    const plaintext = carrierBytes(input, 'plaintextBase64url', id);
    const aad = carrierBytes(input, 'aadBase64url', id);
    checkAesWidths(keyBytes, nonce, id);

    const key = await importRaw(keyBytes, 'AES-GCM', ['encrypt'], `request ${id} carries a key this bridge cannot import`);
    const carrier = await subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: GCM_TAG_BITS },
        key,
        plaintext,
    );

    return { ciphertextBase64url: encodeBase64url(new Uint8Array(carrier)) };
}

/**
 * One ECDH agreement over P-256: the private half arrives as a JWK, the peer's
 * public half as a 65-octet uncompressed SEC 1 point imported `raw`.
 * `deriveBits` answers the agreed x-coordinate at the field width, so the 32
 * octets keep every leading zero a big integer would drop. No KDF runs over the
 * secret, and the operation defines no refusal.
 */
async function observeEcdhP256(input, id) {
    closedMembers(input, ['privateKeyJwk', 'peerPointBase64url'], `the input of request ${id}`);
    const privateKey = await importJwk(input, 'privateKeyJwk', ECDH_P256, ['deriveBits'], false, id);
    const point = carrierBytes(input, 'peerPointBase64url', id);
    if (point.length !== P256_POINT_OCTETS) {
        throw new BridgeFault(`request ${id} carries a peer point of ${point.length} octet(s), and a P-256 point is ${P256_POINT_OCTETS}.`);
    }

    let peer;
    try {
        peer = await subtle.importKey('raw', point, ECDH_P256, false, []);
    } catch (error) {
        throw new BridgeFault(`request ${id} carries a peer point this bridge cannot import: ${error.message}.`);
    }

    const secret = await subtle.deriveBits({ name: 'ECDH', public: peer }, privateKey, P256_FIELD_BITS);
    return { sharedSecretBase64url: encodeBase64url(new Uint8Array(secret)) };
}

/**
 * One P-256 public key, written as the uncompressed SEC 1 point `exportKey`
 * answers `raw` with: the octet 0x04 and both coordinates at their full 32-octet
 * width, so a coordinate that starts with a zero octet keeps it. The key is
 * imported extractable, because the operation exports it.
 */
async function observeP256Point(input, id) {
    closedMembers(input, ['publicKeyJwk'], `the input of request ${id}`);
    const publicKey = await importJwk(input, 'publicKeyJwk', ECDH_P256, [], true, id);
    const point = await subtle.exportKey('raw', publicKey);
    return { pointBase64url: encodeBase64url(new Uint8Array(point)) };
}

/**
 * One RSA-OAEP decryption under SHA-256, MGF1 on the same hash and no label, and
 * the whole plaintext comes back with nothing read out of it. A wrong private
 * key, a ciphertext that is not one modulus wide and a flipped octet are one
 * padding failure, and a bridge saying which one happened would answer the
 * question a padding oracle asks.
 */
async function observeOpenRsaOaep(input, id) {
    closedMembers(input, ['ciphertextBase64url', 'privateKeyJwk'], `the input of request ${id}`);
    const privateKey = await importJwk(input, 'privateKeyJwk', RSA_OAEP_SHA256, ['decrypt'], false, id);
    const carrier = carrierBytes(input, 'ciphertextBase64url', id);

    let plaintext;
    try {
        plaintext = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, carrier);
    } catch {
        // WebCrypto reports a padding failure as a rejection, and this catch
        // reads every rejection as that refusal without checking the error's
        // name, for the reason the AES-GCM open above gives. A runtime that
        // cannot run RSA-OAEP at all rejects here too, and then the success
        // cases in the same set disagree.
        return { refused: 'unseal_failed' };
    }

    return { plaintextBase64url: encodeBase64url(new Uint8Array(plaintext)) };
}

/** The two AES-GCM widths the contract fixes; anything else is a batch fault. */
function checkAesWidths(key, nonce, id) {
    if (!AES_KEY_OCTETS.includes(key.length)) {
        throw new BridgeFault(`request ${id} carries a ${key.length}-octet key, and AES-GCM here takes ${AES_KEY_OCTETS.join(' or ')}.`);
    }
    if (nonce.length !== GCM_NONCE_OCTETS) {
        throw new BridgeFault(`request ${id} carries a ${nonce.length}-octet nonce, and AES-GCM here takes ${GCM_NONCE_OCTETS}.`);
    }
}

/** One raw key, imported for one algorithm, or a request this bridge cannot serve. */
async function importRaw(bytes, algorithm, usages, what) {
    try {
        return await subtle.importKey('raw', bytes, algorithm, false, usages);
    } catch (error) {
        throw new BridgeFault(`${what}: ${error.message}.`);
    }
}

/** One JWK input member, imported by the runtime's own JWK reader. */
async function importJwk(input, member, algorithm, usages, extractable, id) {
    const jwk = requiredObject(input, member, id);
    try {
        return await subtle.importKey('jwk', jwk, algorithm, extractable, usages);
    } catch (error) {
        throw new BridgeFault(`request ${id} carries a ${member} this bridge cannot import: ${error.message}.`);
    }
}

/**
 * One JSON object holding exactly the named members, or a request this bridge
 * cannot serve.
 *
 * The contract calls the envelope, the request row and every input closed, and a
 * closed shape holds only if something checks it. A member outside the
 * set means the sender writes a protocol this bridge has not agreed to, and a
 * missing one means it left out something the operation is defined by.
 */
function closedMembers(object, members, what) {
    const present = Object.keys(object);
    const unknown = present.filter((name) => !members.includes(name));
    const absent = members.filter((name) => !present.includes(name));
    if (unknown.length > 0 || absent.length > 0) {
        throw new BridgeFault(`${what} carries {${present.join(', ')}}, and it carries {${members.join(', ')}} exactly.`);
    }
}

/** One input member that must be present and a string, or a request this bridge cannot serve. */
function requiredString(input, member, id) {
    if (typeof input[member] !== 'string') {
        throw new BridgeFault(`request ${id} carries no string ${member}.`);
    }
    return input[member];
}

/** One finite JSON integer, or a request this bridge cannot serve. */
function requiredInteger(input, member, id) {
    if (!Number.isSafeInteger(input[member])) {
        throw new BridgeFault(`request ${id} carries no integer ${member}.`);
    }
    return input[member];
}

/** One input member that must be present and a JSON object, or a request this bridge cannot serve. */
function requiredObject(input, member, id) {
    if (!isPlainObject(input[member])) {
        throw new BridgeFault(`request ${id} carries no ${member} object.`);
    }
    return input[member];
}

/**
 * One base64url input member decoded to raw octets. Every value the harness sends
 * is canonical, so a spelling that is not means the batch was written wrong, and
 * this bridge ends the batch naming the request. `decode-base64url` is where a
 * spelling is the subject.
 */
function carrierBytes(input, member, id) {
    const value = requiredString(input, member, id);
    const bytes = decodeStrictBase64url(value);
    if (bytes === null) {
        throw new BridgeFault(`request ${id} carries a ${member} this bridge cannot decode.`);
    }
    return bytes;
}

/**
 * Canonical unpadded base64url to octets, or `null` when the value is not
 * canonical.
 *
 * Four checks, the contract's own four: the alphabet, a length that encodes a
 * whole byte count, no padding (the alphabet check again, since `=` is outside
 * it), and no unused trailing bits, read by decoding and re-encoding and
 * comparing against the input. No runtime decoder applies that last rule by
 * itself, which is why it is written out here rather than left to `Buffer`.
 */
function decodeStrictBase64url(value) {
    if (!/^[A-Za-z0-9_-]*$/.test(value)) return null;
    if (value.length % 4 === 1) return null;

    const bytes = new Uint8Array(Buffer.from(value, 'base64url'));
    if (encodeBase64url(bytes) !== value) return null;

    return bytes;
}

/** Octets to canonical unpadded base64url. */
function encodeBase64url(bytes) {
    return Buffer.from(bytes).toString('base64url');
}

function isPlainObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
