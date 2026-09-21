<?php
// PHP probe. Reads `_shared/fixture.json` inputs, seals and opens the three
// envelope profiles through openssl, and writes observations as JSON on
// stdout. It reads no expectation and assigns no verdict.

declare(strict_types=1);

const TAG_BYTES = 16;

// The two SubjectPublicKeyInfo shells for a P-256 point: id-ecPublicKey with
// prime256v1, then a BIT STRING holding the 65-byte or 33-byte point. openssl
// has no raw-point entry, so every import here is container-assisted.
const SPKI_65 = '3059301306072a8648ce3d020106082a8648ce3d030107034200';
const SPKI_33 = '3039301306072a8648ce3d020106082a8648ce3d030107032200';

$fixture = json_decode(file_get_contents(__DIR__ . '/../_shared/fixture.json'), true);
$inputs = $fixture['inputs'];

function pem(string $der, string $label): string
{
    return "-----BEGIN $label-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $label-----\n";
}

function import_point(string $point)
{
    $shell = strlen($point) === 33 ? SPKI_33 : SPKI_65;
    return @openssl_pkey_get_public(pem(hex2bin($shell) . $point, 'PUBLIC KEY'));
}

function import_private(string $pkcs8Hex)
{
    return openssl_pkey_get_private(pem(hex2bin($pkcs8Hex), 'PRIVATE KEY'));
}

/** @return string|null the 32-byte fixed-width x-coordinate, or null when import or agreement fails */
function agree(string $point, string $pkcs8Hex): ?string
{
    $public = import_point($point);
    if ($public === false) {
        return null;
    }
    $shared = @openssl_pkey_derive($public, import_private($pkcs8Hex), 32);
    return $shared === false ? null : $shared;
}

function hkdf(string $secret, string $info, int $length): string
{
    return hash_hkdf('sha256', $secret, $length, $info, '');
}

function gcm_seal(string $key, string $nonce, string $plaintext, string $aad): string
{
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, TAG_BYTES);
    return $ciphertext . $tag;
}

/** @return string|false */
function gcm_open(string $key, string $nonce, string $carrier, string $aad)
{
    if (strlen($carrier) <= TAG_BYTES) {
        return false;
    }
    $ciphertext = substr($carrier, 0, -TAG_BYTES);
    $tag = substr($carrier, -TAG_BYTES);
    return @openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
}

// One profile switch, shared by the three shapes: how wide the carried point
// is, and whether the key and nonce come from the fixture or from HKDF.
$profiles = [
    'control-109' => ['point' => 'publicUncompressedHex', 'derived' => false],
    'hkdf-97' => ['point' => 'publicUncompressedHex', 'derived' => true],
    'hkdf-compressed-65' => ['point' => 'publicCompressedHex', 'derived' => true],
];

/** @return array{key: string, nonce: string}|null */
function material(array $inputs, bool $derived, ?string $shared, string $bind): ?array
{
    if ($shared === null) {
        return null;
    }
    if (!$derived) {
        return ['key' => $shared, 'nonce' => hex2bin($inputs['controlNonceHex'])];
    }
    return [
        'key' => hkdf($shared, $inputs['hkdf']['keyInfoPrefix'] . $bind, $inputs['hkdf']['keyBytes']),
        'nonce' => hkdf($shared, $inputs['hkdf']['nonceInfoPrefix'] . $bind, $inputs['hkdf']['nonceBytes']),
    ];
}

function point_bytes(string $profile): int
{
    return $profile === 'hkdf-compressed-65' ? 33 : 65;
}

/** @return string|false the recovered payload */
function open_envelope(array $inputs, array $profiles, string $profile, string $envelope, string $bind)
{
    $width = point_bytes($profile);
    $point = substr($envelope, 0, $width);
    $derived = $profiles[$profile]['derived'];
    $rest = substr($envelope, $width);
    $material = material($inputs, $derived, agree($point, $inputs['issuer']['privatePkcs8Hex']), $bind);
    if ($material === null) {
        return false;
    }
    if ($derived) {
        return gcm_open($material['key'], $material['nonce'], $rest, $bind);
    }
    return gcm_open($material['key'], substr($rest, 0, 12), substr($rest, 12), $bind);
}

// The probe reports every negative case as one word. The experiment looks for a
// released key, so the probe reports which of the two happened and
// nothing about the cause.
function releases(array $inputs, array $profiles, string $profile, string $envelope, string $bind): string
{
    $opened = open_envelope($inputs, $profiles, $profile, $envelope, $bind);
    return ($opened === false || $opened === '') ? 'no-key' : 'key-released';
}

function base64url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

$compressedMode = import_point(hex2bin($inputs['ephemeral']['publicCompressedHex'])) === false
    ? 'unsupported'
    : 'container-assisted';

$bind = $inputs['bind']['value'];
$observations = [
    'runtime' => 'php',
    'runtimeVersion' => PHP_VERSION,
    'cryptoProvider' => OPENSSL_VERSION_TEXT,
    'compressedPointImport' => $compressedMode,
    'profiles' => [],
    'ephemeralReuse' => [],
];

foreach ($profiles as $profile => $shape) {
    $point = hex2bin($inputs['ephemeral'][$shape['point']]);
    if (strlen($point) === 33 && $compressedMode === 'unsupported') {
        $observations['profiles'][$profile] = [
            'status' => 'unsupported',
            'reason' => 'no compressed-point import through the runtime',
        ];
        continue;
    }

    // The publisher side agrees with the issuer public point under the fixed
    // ephemeral private key, so every runtime seals the same bytes.
    $sealing = material(
        $inputs,
        $shape['derived'],
        agree(hex2bin($inputs['issuer']['publicUncompressedHex']), $inputs['ephemeral']['privatePkcs8Hex']),
        $bind
    );
    $carrier = gcm_seal($sealing['key'], $sealing['nonce'], hex2bin($inputs['dcaKeyHex']), $bind);
    $envelope = $shape['derived'] ? $point . $carrier : $point . $sealing['nonce'] . $carrier;

    $flipped = $envelope;
    $at = strlen($flipped) - TAG_BYTES - 1;
    $flipped[$at] = chr(ord($flipped[$at]) ^ 0x01);

    $badPoint = hex2bin(strlen($point) === 33
        ? $inputs['offCurvePoints']['compressedHex']
        : $inputs['offCurvePoints']['uncompressedHex']);
    $offCurve = $badPoint . substr($envelope, strlen($point));

    // A compressed x below p whose curve equation has no square root mod p.
    // Only a 33-byte point carries that case, so the probe records `n/a` for the wider profiles.
    $nonResidue = 'n/a';
    if (strlen($point) === 33) {
        $nonResidueEnvelope = hex2bin($inputs['offCurvePoints']['compressedNonResidueHex'])
            . substr($envelope, strlen($point));
        $nonResidue = releases($inputs, $profiles, $profile, $nonResidueEnvelope, $bind);
    }

    $opened = open_envelope($inputs, $profiles, $profile, $envelope, $bind);

    $observations['profiles'][$profile] = [
        'status' => 'answered',
        'envelopeHex' => bin2hex($envelope),
        'derivedKeyHex' => bin2hex($sealing['key']),
        'derivedNonceHex' => bin2hex($sealing['nonce']),
        'envelopeBase64url' => base64url($envelope),
        'decodedBytes' => strlen($envelope),
        'base64urlChars' => strlen(base64url($envelope)),
        'pointBytes' => strlen($point),
        'openedKeyHex' => $opened === false ? 'open-failed' : bin2hex($opened),
        'wrongBind' => releases($inputs, $profiles, $profile, $envelope, $inputs['otherBind']['value']),
        'flippedCiphertext' => releases($inputs, $profiles, $profile, $flipped, $bind),
        'invalidPoint' => releases($inputs, $profiles, $profile, $offCurve, $bind),
        'nonResiduePoint' => $nonResidue,
    ];
}

$derivedPair = function (string $pkcs8Hex, string $bind) use ($inputs): array {
    $shared = agree(hex2bin($inputs['issuer']['publicUncompressedHex']), $pkcs8Hex);
    return [
        'keyHex' => bin2hex(hkdf($shared, $inputs['hkdf']['keyInfoPrefix'] . $bind, $inputs['hkdf']['keyBytes'])),
        'nonceHex' => bin2hex(hkdf($shared, $inputs['hkdf']['nonceInfoPrefix'] . $bind, $inputs['hkdf']['nonceBytes'])),
    ];
};

$pairs = [
    'sameEphemeralSameBind' => $derivedPair($inputs['ephemeral']['privatePkcs8Hex'], $bind),
    'sameEphemeralSameBindRepeat' => $derivedPair($inputs['ephemeral']['privatePkcs8Hex'], $bind),
    'sameEphemeralOtherBind' => $derivedPair($inputs['ephemeral']['privatePkcs8Hex'], $inputs['otherBind']['value']),
    'freshEphemeralSameBind' => $derivedPair($inputs['ephemeralFresh']['privatePkcs8Hex'], $bind),
];
foreach ($profiles as $profile => $shape) {
    if ($shape['derived']) {
        $observations['ephemeralReuse'][$profile] = $pairs;
    }
}

echo json_encode($observations, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
