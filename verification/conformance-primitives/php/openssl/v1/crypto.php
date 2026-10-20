<?php
/**
 * The primitives `bridge.php` needs and PHP has no single call for: JWK to PEM
 * for the two key types this lane imports, unpadded base64url over a JWK's own
 * coordinate members, AES-GCM over the `ciphertext || tag` layout the bridge
 * reads and writes, HKDF-SHA-256 over octets a caller passes in, and the
 * RSA-OAEP-SHA256 padding `openssl_private_decrypt` will not do above SHA-1.
 *
 * Nothing here reads a batch, a case or an argv. This file holds functions, and
 * requiring it runs none of them.
 *
 * Dependencies: ext-openssl and ext-hash, same as `bridge.php`.
 */

/**
 * JWK to PEM. P-256 fixed-length DER templates; openssl reads no JWK.
 * The PEM armor below wraps a test key the request carries; this file holds no
 * key material of its own.
 */
function jwkPrivateToPem(array $jwk)
{
    $d = b64u($jwk['d']);
    $der = "\x30\x77\x02\x01\x01\x04\x20" . $d
        . "\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
        . "\xa1\x44\x03\x42\x00" . pointFromJwk($jwk);
    return "-----BEGIN EC PRIVATE KEY-----\n"
        . chunk_split(base64_encode($der), 64, "\n") . "-----END EC PRIVATE KEY-----\n";
}

/** The uncompressed SEC 1 point, 0x04 then x then y, each coordinate at its full 32 octets. */
function pointFromJwk(array $jwk)
{
    return "\x04" . str_pad(b64u($jwk['x']), 32, "\x00", STR_PAD_LEFT)
        . str_pad(b64u($jwk['y']), 32, "\x00", STR_PAD_LEFT);
}

function rawPointToPem($raw)
{
    $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . $raw;
    return "-----BEGIN PUBLIC KEY-----\n"
        . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

/** base64url, unpadded, spelled out. */
function b64u($s)
{
    // PHP's strict decoder still accepts whitespace. A member arrives unpadded
    // and in the base64url alphabet, so admit only that spelling here.
    if (!is_string($s) || preg_match('/\A[A-Za-z0-9_-]*\z/D', $s) !== 1 || strlen($s) % 4 === 1) {
        return false;
    }
    $padded = strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4);
    return base64_decode($padded, true);
}

/** Picks the cipher from the key's width: 16 octets AES-128-GCM, 32 octets AES-256-GCM. */
function gcmCipher($key)
{
    return strlen($key) === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
}

/** Opens one carrier, reading its last 16 octets as the tag openssl takes beside the buffer. */
function gcmOpen($key, $nonce, $ctAndTag, $aad)
{
    $tag = substr($ctAndTag, -16);
    $ct = substr($ctAndTag, 0, -16);
    return openssl_decrypt($ct, gcmCipher($key), $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
}

/** Ciphertext with the 16-octet tag appended, in the layout the contract names. */
function gcmSeal($key, $nonce, $plaintext, $aad)
{
    $tag = '';
    $ct = openssl_encrypt($plaintext, gcmCipher($key), $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
    return $ct === false ? false : $ct . $tag;
}

/**
 * One HKDF-SHA-256 derivation with an empty salt, RFC 5869. `hash_hkdf`
 * extracts and expands in one call. A PHP string carries arbitrary octets, so
 * `$info` reaches `hash_hkdf` as the caller wrote it.
 */
function hkdfSha256($ikm, $info, $length)
{
    return hash_hkdf('sha256', $ikm, $length, $info, '');
}

/**
 * A DER INTEGER (0x02) around a big-endian magnitude: strip surplus leading
 * zero octets, and prepend one 0x00 when the top bit is set so the value stays
 * positive. The RSA private-key template below needs this one primitive, and
 * openssl builds none of it from a JWK.
 */
function derInteger($magnitude)
{
    $magnitude = ltrim($magnitude, "\x00");
    if ($magnitude === '') {
        $magnitude = "\x00";
    }
    if (ord($magnitude[0]) & 0x80) {
        $magnitude = "\x00" . $magnitude;
    }
    return "\x02" . derLength(strlen($magnitude)) . $magnitude;
}

/** DER length octets, short form under 128 and long form (0x80|n) above. */
function derLength($n)
{
    if ($n < 0x80) {
        return chr($n);
    }
    $bytes = '';
    while ($n > 0) {
        $bytes = chr($n & 0xff) . $bytes;
        $n >>= 8;
    }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

/**
 * RSA private JWK to PKCS#1 PEM. openssl reads no JWK, so this assembles the
 * PKCS#1 RSAPrivateKey SEQUENCE from the members the request carries, n, e, d,
 * p, q, dp, dq and qi, in the fixed order below. It is the same shape
 * `jwkPrivateToPem` builds for P-256, with variable-length integers. The key is
 * used here only for the raw modexp under OPENSSL_NO_PADDING, because stock
 * openssl OAEP is SHA-1 and `oaepDecodeSha256` below unpads at SHA-256.
 */
function rsaJwkPrivateToPem(array $jwk)
{
    $seq = derInteger("\x00")                     // version 0
        . derInteger(b64u($jwk['n']))             // modulus
        . derInteger(b64u($jwk['e']))             // publicExponent
        . derInteger(b64u($jwk['d']))             // privateExponent
        . derInteger(b64u($jwk['p']))             // prime1
        . derInteger(b64u($jwk['q']))             // prime2
        . derInteger(b64u($jwk['dp']))            // exponent1
        . derInteger(b64u($jwk['dq']))            // exponent2
        . derInteger(b64u($jwk['qi']));           // coefficient
    $der = "\x30" . derLength(strlen($seq)) . $seq;
    // Armor for a test key the request carries, not a stored key.
    return "-----BEGIN RSA PRIVATE KEY-----\n"
        . chunk_split(base64_encode($der), 64, "\n") . "-----END RSA PRIVATE KEY-----\n";
}

/**
 * MGF1 with SHA-256, RFC 8017 B.2.1: T = T || Hash(seed || C) for a 4-byte
 * big-endian counter C, truncated to $length. It sits beside the OAEP decode
 * below, so this file shows how a PHP implementation holding nothing but
 * openssl_* rebuilds the padding.
 */
function mgf1Sha256($seed, $length)
{
    $out = '';
    $counter = 0;
    while (strlen($out) < $length) {
        $out .= hash('sha256', $seed . pack('N', $counter), true);
        $counter++;
    }
    return substr($out, 0, $length);
}

/**
 * EME-OAEP decode with SHA-256, empty label, RFC 8017 7.1.2, the inverse of the
 * seal openssl will not do above SHA-1. Every failure folds into one error, so
 * a padding oracle learns nothing about which check failed. Returns the message
 * octets, or false on any padding failure (this lane does not need the
 * constant-time throw).
 */
function oaepDecodeSha256($em, $k)
{
    $hLen = 32;
    if (strlen($em) !== $k || $k < 2 * $hLen + 2) {
        return false;
    }
    $fail = false;
    // 7.1.2 step 3b: EM = Y || maskedSeed || maskedDB.
    $y = $em[0];
    $maskedSeed = substr($em, 1, $hLen);
    $maskedDb = substr($em, 1 + $hLen);
    // 7.1.2 step 3c-3f: unmask the seed, then the data block.
    $seed = $maskedSeed ^ mgf1Sha256($maskedDb, $hLen);
    $db = $maskedDb ^ mgf1Sha256($seed, $k - $hLen - 1);
    // 7.1.2 step 3a + 3g: DB = lHash' || PS || 0x01 || M.
    $lHash = hash('sha256', '', true);
    if (!hash_equals($lHash, substr($db, 0, $hLen))) {
        $fail = true;
    }
    $rest = substr($db, $hLen);
    $sep = strpos($rest, "\x01");
    if ($sep === false) {
        $fail = true;
        $sep = 0;
    }
    if (strlen(str_replace("\x00", '', substr($rest, 0, $sep))) !== 0) {
        $fail = true;
    }
    if ($y !== "\x00") {
        $fail = true;
    }
    if ($fail) {
        return false;
    }
    return substr($rest, $sep + 1);
}
