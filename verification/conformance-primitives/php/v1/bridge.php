<?php
/**
 * What PHP observes when it runs one of the contract's seven library calls, and
 * nothing about whether that observation is right.
 *
 * The bridge reads a single
 * `dca-operation-bridge-v1` JSON document from stdin, computes one observation
 * per request, writes a single JSON document to stdout and exits 0. Human
 * diagnostics go to stderr; nothing reads a result out of stderr, so a bridge
 * may say whatever it likes there.
 *
 * The bridge does not know what any observation is supposed to be. There is no
 * expected value here, no comparison, no `held`, `disagreed` or `incomplete`
 * word, no pass count and no total. It never opens the case corpus, and the
 * request it is handed carries no `expected` for it to peek at. If a bridge
 * can read the answer, nobody has tested it, and if a bridge reports
 * its own verdict, the harness has a second opinion to reconcile.
 *
 * Each operation is one stock call: decode a strict base64url field, derive
 * octets with HKDF-SHA-256, open and seal an AES-GCM carrier, agree a P-256
 * ECDH secret, encode a P-256 public point, open an RSA-OAEP ciphertext.
 * `crypto.php` holds what PHP has no single call for: JWK to PEM for both key
 * types, AES-GCM over the `ciphertext || tag` layout, and the RSA-OAEP-SHA256
 * padding stock `openssl_private_decrypt` will not do above SHA-1. Each handler
 * below adds this file's own shape checks, encoding and refusal mapping to one
 * of those calls.
 *
 * The bridge reports a defined refusal as an answer. `invalid_base64url`,
 * `authentication_failed` and `unseal_failed` are observations inside an exit-0
 * result, because refusing correctly is one of the behaviours under test. For a
 * request the bridge cannot serve at all, an unparseable batch, an unknown
 * operation or an input shape outside the contract, the bridge exits nonzero with a stderr
 * line and writes no partial results, and the runner reads that as a run nobody
 * completed. A key the bridge cannot import, and an agreement openssl will not
 * perform, are faults of that kind: the refusal codes belong to a carrier that
 * did not open, never to a key.
 *
 * The bridge checks every shape it reads, and each one is closed. The envelope
 * carries `protocol` and `requests`, a request row carries `id`, `op` and
 * `input`, and an input carries exactly the members its operation names. A
 * member nobody named means the sender speaks a protocol this bridge has not
 * agreed to, and answering it anyway would let a request quietly carry
 * something the contract keeps out.
 *
 * The bridge reads the batch with PHP's own JSON parser and nothing else. There
 * is no token scanner here. `json_decode` keeps one spelling of a repeated
 * member and says nothing, and this bridge does not go looking: the harness
 * writes the bytes on stdin and never repeats a member, so a bridge guarding
 * against one would guard against its own harness, once per language.
 *
 * Dependencies: ext-json and ext-openssl. Verified on PHP 8.3.33.
 *
 * Run (the runner does this; by hand it is the same):
 *   printf '%s\n' '<batch json>' | php conformance-primitives/php/v1/bridge.php
 */

declare(strict_types=1);

// The CLI SAPI's display_errors defaults to stdout, so an ordinary PHP Warning,
// a malformed IV length or an undefined array key inside a key builder, would
// otherwise land in front of the JSON this bridge writes there. Pinned here,
// first, before crypto.php or anything else can raise one.
ini_set('display_errors', 'stderr');

require __DIR__ . '/crypto.php';

const BATCH_PROTOCOL = 'dca-operation-bridge-v1';

/** The output widths `hkdf-sha256` derives, from the contract's HKDF-SHA-256 section. */
const HKDF_MIN_OCTETS = 1;
const HKDF_MAX_OCTETS = 8160;

/** The P-256 field width, which fixes a coordinate and an agreed secret at 32 octets. */
const P256_FIELD_OCTETS = 32;

/** A batch or a request this bridge cannot serve, which is never a refusal. */
final class BridgeFault extends RuntimeException
{
}

exit(main());

function main(): int
{
    $raw = stream_get_contents(STDIN);
    if ($raw === false) {
        fwrite(STDERR, "bridge: stdin could not be read.\n");
        return 1;
    }

    try {
        $results = answerBatch($raw);
    } catch (BridgeFault $fault) {
        fwrite(STDERR, 'bridge: ' . $fault->getMessage() . "\n");
        return 1;
    } catch (Throwable $error) {
        fwrite(STDERR, 'bridge: ' . get_class($error) . ': ' . $error->getMessage() . "\n");
        return 1;
    }

    $envelope = ['protocol' => BATCH_PROTOCOL, 'results' => $results];
    $encoded = json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    fwrite(STDOUT, $encoded . "\n");
    return 0;
}

/**
 * The request envelope, read strictly, and one result per request in request order.
 *
 * Order is irrelevant to the runner, which keys results by the (id, op) pair, so
 * request order is kept only because it makes a hand-read batch easy to follow.
 */
function answerBatch(string $raw): array
{
    try {
        $request = json_decode($raw, false, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException $error) {
        throw new BridgeFault('the batch on stdin is not readable JSON: ' . $error->getMessage());
    }
    if (!($request instanceof stdClass)) {
        throw new BridgeFault('the batch on stdin is not a JSON object.');
    }
    closedMembers($request, ['protocol', 'requests'], 'the batch');
    if (!is_string($request->protocol) || $request->protocol !== BATCH_PROTOCOL) {
        throw new BridgeFault('the batch names a protocol this bridge does not speak.');
    }
    if (!is_array($request->requests)) {
        throw new BridgeFault('the batch carries no requests array.');
    }

    $results = [];
    foreach ($request->requests as $entry) {
        if (!($entry instanceof stdClass)) {
            throw new BridgeFault('a request entry is not a JSON object.');
        }
        closedMembers($entry, ['id', 'op', 'input'], 'a request entry');
        if (!is_string($entry->id) || $entry->id === '') {
            throw new BridgeFault('a request entry carries no id.');
        }
        if (!is_string($entry->op)) {
            throw new BridgeFault(sprintf('request %s carries no op.', $entry->id));
        }
        if (!($entry->input instanceof stdClass)) {
            throw new BridgeFault(sprintf('request %s carries no input object.', $entry->id));
        }

        $results[] = [
            'id' => $entry->id,
            'op' => $entry->op,
            'observation' => observe($entry->op, $entry->input, $entry->id),
        ];
    }

    return $results;
}

/** One observation for one request, or a fault if the operation is not one of the seven. */
function observe(string $op, stdClass $input, string $id): array
{
    switch ($op) {
        case 'decode-base64url':
            return observeDecodeBase64url($input, $id);
        case 'hkdf-sha256':
            return observeHkdfSha256($input, $id);
        case 'open-aes-gcm':
            return observeOpenAesGcm($input, $id);
        case 'seal-aes-gcm':
            return observeSealAesGcm($input, $id);
        case 'ecdh-p256':
            return observeEcdhP256($input, $id);
        case 'p256-point':
            return observeP256Point($input, $id);
        case 'open-rsa-oaep':
            return observeOpenRsaOaep($input, $id);
        default:
            throw new BridgeFault(sprintf('request %s names operation %s, which this bridge does not implement.', $id, $op));
    }
}

/**
 * The strict field spelling: RFC 4648 section 5 alphabet, no padding, a length
 * that encodes a whole byte count, and zero unused trailing bits.
 *
 * The bridge writes which of those rules fired to stderr. The observation carries the one
 * closed code, because the contract has one.
 */
function observeDecodeBase64url(stdClass $input, string $id): array
{
    closedMembers($input, ['value'], sprintf('the input of request %s', $id));
    $value = requiredString($input, 'value', $id);
    $bytes = decodeStrictBase64url($value, $why);
    if ($bytes === null) {
        fwrite(STDERR, sprintf("bridge: %s refused %s: %s\n", $id, json_encode($value), $why));
        return ['refused' => 'invalid_base64url'];
    }
    return ['bytesHex' => bin2hex($bytes)];
}

/**
 * One HKDF-SHA-256 derivation, RFC 5869, over the octets the request carries,
 * with an empty salt. PHP's `hash_hkdf` extracts and expands in one call, and it
 * reads an empty salt as 32 zero octets, which RFC 5869 defines as the same
 * derivation.
 *
 * The bridge hands `info` to `hash_hkdf` as it arrived: PHP strings hold
 * arbitrary octets, so the 0x00 and the octets above 0x7f a caller sends reach
 * `hash_hkdf` unchanged. An `ikm` or an `info` outside canonical base64url, and
 * a `length` outside 1 through 8160, are requests this bridge cannot serve.
 */
function observeHkdfSha256(stdClass $input, string $id): array
{
    closedMembers($input, ['ikmBase64url', 'infoBase64url', 'length'], sprintf('the input of request %s', $id));
    $ikm = carrierBytes($input, 'ikmBase64url', $id);
    $info = carrierBytes($input, 'infoBase64url', $id);
    $length = requiredInteger($input, 'length', $id);
    if ($length < HKDF_MIN_OCTETS || $length > HKDF_MAX_OCTETS) {
        throw new BridgeFault(sprintf(
            'request %s asks for %d HKDF octets, and this operation derives %d through %d.',
            $id,
            $length,
            HKDF_MIN_OCTETS,
            HKDF_MAX_OCTETS,
        ));
    }

    return ['okmBase64url' => encodeBase64url(hkdfSha256($ikm, $info, $length))];
}

/**
 * One AES-GCM carrier opened. The key's width picks the cipher, 16 octets
 * AES-128-GCM and 32 octets AES-256-GCM, and `ciphertextBase64url` decodes to
 * `ciphertext || tag` in one buffer, which `crypto.php` splits for the openssl
 * call that takes the tag beside it. `aadBase64url` may be the empty string,
 * and openssl then authenticates empty additional data.
 */
function observeOpenAesGcm(stdClass $input, string $id): array
{
    closedMembers(
        $input,
        ['keyBase64url', 'nonceBase64url', 'ciphertextBase64url', 'aadBase64url'],
        sprintf('the input of request %s', $id),
    );
    $key = aeadKeyBytes($input, 'keyBase64url', $id);
    $nonce = nonceBytes($input, 'nonceBase64url', $id);
    $carrier = carrierBytes($input, 'ciphertextBase64url', $id);
    $aad = carrierBytes($input, 'aadBase64url', $id);

    // A decoded carrier too short to hold its own tag authenticates under no
    // key, so the bridge answers it with this operation's refusal rather than a fault: the
    // base64url decoded, and what it decoded to is too short for its fields.
    $plaintext = strlen($carrier) < 16 ? false : @gcmOpen($key, $nonce, $carrier, $aad);
    if ($plaintext === false) {
        fwrite(STDERR, sprintf("bridge: %s did not authenticate.\n", $id));
        return ['refused' => 'authentication_failed'];
    }

    return ['plaintextBase64url' => encodeBase64url($plaintext)];
}

/**
 * One AES-GCM seal, at the same widths, answering the ciphertext with the
 * 16-octet tag appended. The nonce arrives as an input, so the
 * seal has one determined answer. The operation defines no refusal, so a seal
 * openssl will not perform is a request this bridge cannot serve.
 */
function observeSealAesGcm(stdClass $input, string $id): array
{
    closedMembers(
        $input,
        ['keyBase64url', 'nonceBase64url', 'plaintextBase64url', 'aadBase64url'],
        sprintf('the input of request %s', $id),
    );
    $key = aeadKeyBytes($input, 'keyBase64url', $id);
    $nonce = nonceBytes($input, 'nonceBase64url', $id);
    $plaintext = carrierBytes($input, 'plaintextBase64url', $id);
    $aad = carrierBytes($input, 'aadBase64url', $id);

    $sealed = gcmSeal($key, $nonce, $plaintext, $aad);
    if ($sealed === false) {
        throw new BridgeFault(sprintf('request %s could not be sealed under %s.', $id, gcmCipher($key)));
    }

    return ['ciphertextBase64url' => encodeBase64url($sealed)];
}

/**
 * One ECDH agreement over P-256. `peerPointBase64url` decodes to the peer's
 * uncompressed SEC 1 point, which `crypto.php` wraps in the SubjectPublicKeyInfo
 * PEM openssl imports, and `openssl_pkey_derive` agrees it against the private
 * JWK the request names.
 *
 * The operation defines no refusal, so a point openssl will not import and an
 * agreement it will not perform are both requests this bridge cannot serve. The
 * answer is the agreed x-coordinate at the field width, left-padded with zero
 * octets, because openssl hands back a magnitude, and in one recorded case the
 * secret starts with a zero octet.
 */
function observeEcdhP256(stdClass $input, string $id): array
{
    closedMembers($input, ['privateKeyJwk', 'peerPointBase64url'], sprintf('the input of request %s', $id));

    $privatePem = ecPrivateKeyPem($input, 'privateKeyJwk', $id);
    $peerPoint = carrierBytes($input, 'peerPointBase64url', $id);
    $peerPem = rawPointToPem($peerPoint);
    if (@openssl_pkey_get_public($peerPem) === false) {
        throw new BridgeFault(sprintf('request %s carries a peerPointBase64url this bridge cannot import.', $id));
    }

    $shared = @openssl_pkey_derive($peerPem, $privatePem);
    if ($shared === false) {
        throw new BridgeFault(sprintf('request %s: the ECDH-P256 agreement failed.', $id));
    }
    if (strlen($shared) > P256_FIELD_OCTETS) {
        throw new BridgeFault(sprintf('request %s agreed %d octets, and P-256 agrees at most %d.', $id, strlen($shared), P256_FIELD_OCTETS));
    }

    return ['sharedSecretBase64url' => encodeBase64url(str_pad($shared, P256_FIELD_OCTETS, "\x00", STR_PAD_LEFT))];
}

/**
 * One P-256 public JWK written as the 65-octet uncompressed SEC 1 point: the
 * octet 0x04, then x, then y. Each coordinate keeps its full 32 octets, so a
 * coordinate the JWK spells with a leading zero octet keeps it.
 */
function observeP256Point(stdClass $input, string $id): array
{
    closedMembers($input, ['publicKeyJwk'], sprintf('the input of request %s', $id));

    return ['pointBase64url' => encodeBase64url(ecPointBytes($input, 'publicKeyJwk', $id))];
}

/**
 * One RSA-OAEP-SHA256 ciphertext, opened to the whole plaintext.
 *
 * `crypto.php`'s `rsaJwkPrivateToPem` builds the PKCS#1 template openssl reads
 * no JWK into; `openssl_private_decrypt` under `OPENSSL_NO_PADDING` performs the one
 * raw modexp with this key, because stock openssl OAEP is SHA-1 and the
 * contract fixes SHA-256, so `oaepDecodeSha256` unpads what openssl only
 * decrypts.
 */
function observeOpenRsaOaep(stdClass $input, string $id): array
{
    closedMembers($input, ['ciphertextBase64url', 'privateKeyJwk'], sprintf('the input of request %s', $id));

    $jwkObject = requiredObject($input, 'privateKeyJwk', $id);
    requireRsaPrivateMembers($jwkObject, 'privateKeyJwk', $id);
    $jwk = (array) $jwkObject;
    $private = @openssl_pkey_get_private(rsaJwkPrivateToPem($jwk));
    $details = $private === false ? false : openssl_pkey_get_details($private);
    if ($private === false || $details === false || !isset($details['rsa']['n'])) {
        throw new BridgeFault(sprintf('request %s carries a privateKeyJwk this bridge cannot import.', $id));
    }
    $width = strlen($details['rsa']['n']);
    $ciphertext = carrierBytes($input, 'ciphertextBase64url', $id);

    $em = '';
    $rawOk = openssl_private_decrypt($ciphertext, $em, $private, OPENSSL_NO_PADDING);
    $plaintext = $rawOk ? oaepDecodeSha256(str_pad($em, $width, "\x00", STR_PAD_LEFT), $width) : false;
    if ($plaintext === false) {
        fwrite(STDERR, sprintf("bridge: %s did not decrypt or unpad under RSA-OAEP-SHA256.\n", $id));
        return ['refused' => 'unseal_failed'];
    }

    return ['plaintextBase64url' => encodeBase64url($plaintext)];
}

/**
 * One JSON object holding exactly the named members, or a request this bridge
 * cannot serve.
 *
 * The contract calls the envelope, the request row and every input closed, and that
 * closure holds only if something checks it. A member outside the
 * set means the sender writes a protocol this bridge has not agreed to, and a
 * missing one means it left out something the operation is defined by.
 */
function closedMembers(stdClass $object, array $members, string $what): void
{
    $present = array_keys(get_object_vars($object));
    $unknown = array_values(array_diff($present, $members));
    $absent = array_values(array_diff($members, $present));

    if ($unknown !== [] || $absent !== []) {
        throw new BridgeFault(sprintf(
            '%s carries {%s}, and it carries {%s} exactly.',
            $what,
            implode(', ', $present),
            implode(', ', $members),
        ));
    }
}

/** One input member that must be present and a string, or a request this bridge cannot serve. */
function requiredString(stdClass $input, string $member, string $id): string
{
    if (!property_exists($input, $member) || !is_string($input->$member)) {
        throw new BridgeFault(sprintf('request %s carries no string %s.', $id, $member));
    }
    return $input->$member;
}

/**
 * One input member that must be present and a JSON integer, or a request this
 * bridge cannot serve. PHP's JSON parser hands back an int for a whole number
 * and a float for everything else, so testing the type does the whole check.
 */
function requiredInteger(stdClass $input, string $member, string $id): int
{
    if (!property_exists($input, $member) || !is_int($input->$member)) {
        throw new BridgeFault(sprintf('request %s carries no integer %s.', $id, $member));
    }
    return $input->$member;
}

/** One input member that must be present and a JSON object, or a request this bridge cannot serve. */
function requiredObject(stdClass $input, string $member, string $id): stdClass
{
    if (!property_exists($input, $member) || !($input->$member instanceof stdClass)) {
        throw new BridgeFault(sprintf('request %s carries no %s object.', $id, $member));
    }
    return $input->$member;
}

/**
 * The six RSA-CRT members a private JWK carries beyond `n` and `e`, `d`, `p`,
 * `q`, `dp`, `dq` and `qi`, each required present and a string before this
 * bridge builds a PEM from them.
 *
 * Without this, a public RSA JWK still loads: `rsaJwkPrivateToPem` collapses a
 * missing member to a zero `derInteger` rather than refusing to build it, and
 * openssl does not check that `d` agrees with `n` and `e` at parse time, so
 * `openssl_pkey_get_private` succeeds and `open-rsa-oaep` answers
 * `unseal_failed` for a key this bridge never actually held. `n` and `e` are
 * not checked here: a missing or malformed one already fails
 * `openssl_pkey_get_private` or the `$details['rsa']['n']` check that follows
 * it, so a second check here would test the same failure twice.
 */
function requireRsaPrivateMembers(stdClass $jwk, string $member, string $id): void
{
    foreach (['d', 'p', 'q', 'dp', 'dq', 'qi'] as $name) {
        if (!property_exists($jwk, $name) || !is_string($jwk->$name)) {
            throw new BridgeFault(sprintf('request %s carries a %s with no string %s.', $id, $member, $name));
        }
    }
}

/** One base64url input member decoded to raw bytes. Every carrier literal is canonical. */
function carrierBytes(stdClass $input, string $member, string $id): string
{
    $value = requiredString($input, $member, $id);
    $bytes = decodeStrictBase64url($value, $why);
    if ($bytes === null) {
        throw new BridgeFault(sprintf('request %s carries a %s this bridge cannot decode: %s.', $id, $member, $why));
    }
    return $bytes;
}

/**
 * One AES-GCM key, 16 octets for AES-128-GCM or 32 for AES-256-GCM. Any other
 * width is a request this bridge cannot serve, because no cipher answers it.
 */
function aeadKeyBytes(stdClass $input, string $member, string $id): string
{
    $bytes = carrierBytes($input, $member, $id);
    if (strlen($bytes) !== 16 && strlen($bytes) !== 32) {
        throw new BridgeFault(sprintf('request %s carries a %d-byte key; AES-GCM takes 16 or 32.', $id, strlen($bytes)));
    }
    return $bytes;
}

/** One base64url input member decoded to exactly 12 bytes, or a request this bridge cannot serve. */
function nonceBytes(stdClass $input, string $member, string $id): string
{
    $bytes = carrierBytes($input, $member, $id);
    if (strlen($bytes) !== 12) {
        throw new BridgeFault(sprintf('request %s carries a %s that is not 12 bytes.', $id, $member));
    }
    return $bytes;
}

/**
 * One EC-P256 private JWK input member, as the PEM `openssl_pkey_derive` reads,
 * import-validated with `openssl_pkey_get_private` first. `crypto.php` builds
 * the PEM by hand from the JWK's own coordinates, because openssl reads no JWK,
 * and a coordinate this bridge cannot turn into a working key is a request it
 * cannot serve: the contract's `refused` codes belong to a carrier, never to a
 * key.
 */
function ecPrivateKeyPem(stdClass $input, string $member, string $id): string
{
    $jwk = (array) requiredObject($input, $member, $id);
    if (!isset($jwk['d']) || !is_string($jwk['d']) || b64u($jwk['d']) === false) {
        throw new BridgeFault(sprintf('request %s carries a %s with no base64url d.', $id, $member));
    }
    ecCoordinates($jwk, $member, $id);
    $pem = jwkPrivateToPem($jwk);
    if (@openssl_pkey_get_private($pem) === false) {
        throw new BridgeFault(sprintf('request %s carries a %s this bridge cannot import.', $id, $member));
    }
    return $pem;
}

/** One EC-P256 public JWK input member as the 65-octet uncompressed SEC 1 point. */
function ecPointBytes(stdClass $input, string $member, string $id): string
{
    $jwk = (array) requiredObject($input, $member, $id);
    ecCoordinates($jwk, $member, $id);
    return pointFromJwk($jwk);
}

/**
 * The `x` and `y` of an EC JWK, each a base64url string no wider than the P-256
 * field. `pointFromJwk` left-pads a shorter one, and a wider one is a request
 * this bridge cannot serve, because the point it would write is not 65 octets.
 */
function ecCoordinates(array $jwk, string $member, string $id): void
{
    foreach (['x', 'y'] as $name) {
        if (!isset($jwk[$name]) || !is_string($jwk[$name])) {
            throw new BridgeFault(sprintf('request %s carries a %s with no string %s.', $id, $member, $name));
        }
        $coordinate = b64u($jwk[$name]);
        if ($coordinate === false || strlen($coordinate) > P256_FIELD_OCTETS) {
            throw new BridgeFault(sprintf('request %s carries a %s whose %s is not a P-256 coordinate.', $id, $member, $name));
        }
    }
}

/**
 * Canonical unpadded base64url to bytes, or null with the reason in $why.
 *
 * The decode/re-encode comparison enforces the trailing-bits rule: no runtime decoder
 * refuses unused trailing bits on its own, so the check is spelled out here.
 */
function decodeStrictBase64url(string $value, ?string &$why = null): ?string
{
    $why = null;
    if ($value === '') {
        return '';
    }
    if (preg_match('/\A[A-Za-z0-9_-]+\z/', $value) !== 1) {
        $why = 'a character outside the base64url alphabet, which includes padding';
        return null;
    }
    if (strlen($value) % 4 === 1) {
        $why = 'a length that encodes no whole byte count';
        return null;
    }

    $padded = strtr($value, '-_', '+/');
    $remainder = strlen($padded) % 4;
    if ($remainder !== 0) {
        $padded .= str_repeat('=', 4 - $remainder);
    }
    $bytes = base64_decode($padded, true);
    if ($bytes === false) {
        $why = 'bytes base64_decode would not read';
        return null;
    }
    if (encodeBase64url($bytes) !== $value) {
        $why = 'unused trailing bits: the value does not re-encode to itself';
        return null;
    }

    return $bytes;
}

/** Raw bytes to canonical unpadded base64url. */
function encodeBase64url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}
