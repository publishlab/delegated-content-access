<?php

declare(strict_types=1);

namespace Dca\TestBridge;

use Dca\TestBridge\Value\CryptoKeyValue;

final class SerializerCryptoKey
{
    /** @param array<string, mixed> $value */
    public static function decode(array $value): CryptoKeyValue
    {
        self::exactKeys($value, ['$type', 'algorithm', 'extractable', 'format', 'keyType', 'usages', 'value']);
        if ($value['$type'] !== 'CryptoKey' || $value['keyType'] !== 'public' || $value['format'] !== 'jwk') {
            throw new \TypeError('bridge CryptoKey has unsupported key type or format');
        }
        if (!is_bool($value['extractable']) || !$value['algorithm'] instanceof \stdClass || !is_array($value['usages']) || !$value['value'] instanceof \stdClass) {
            throw new \TypeError('bridge CryptoKey has malformed metadata');
        }
        $algorithm = get_object_vars($value['algorithm']);
        self::exactKeys($algorithm, ['name', 'namedCurve']);
        if (($algorithm['name'] ?? null) !== 'ECDSA' || ($algorithm['namedCurve'] ?? null) !== 'P-256') {
            throw new \TypeError('bridge CryptoKey algorithm is unsupported');
        }
        if ($value['usages'] !== ['verify']) {
            throw new \TypeError('bridge CryptoKey usages are unsupported');
        }
        $jwk = get_object_vars($value['value']);
        foreach (['kty' => 'EC', 'crv' => 'P-256'] as $name => $expected) {
            if (($jwk[$name] ?? null) !== $expected) {
                throw new \TypeError('bridge CryptoKey JWK is not P-256 public material');
            }
        }
        if (isset($jwk['d']) || !is_string($jwk['x'] ?? null) || !is_string($jwk['y'] ?? null)) {
            throw new \TypeError('bridge CryptoKey JWK is not public material');
        }
        if (($jwk['ext'] ?? null) !== $value['extractable'] || !isset($jwk['key_ops']) || !is_array($jwk['key_ops']) || !array_is_list($jwk['key_ops']) || $jwk['key_ops'] !== $value['usages']) {
            throw new \TypeError('bridge CryptoKey JWK metadata does not match transport metadata');
        }
        $x = self::base64url($jwk['x']);
        $y = self::base64url($jwk['y']);
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            throw new \TypeError('bridge CryptoKey JWK point is not P-256');
        }
        $der = "\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42\x00\x04" . $x . $y;
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);
        if (!$key instanceof \OpenSSLAsymmetricKey) {
            throw new \TypeError('bridge CryptoKey JWK could not become an OpenSSL key');
        }
        return new CryptoKeyValue($key, $value['keyType'], $algorithm, $value['extractable'], $value['usages']);
    }

    private static function base64url(string $value): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]*$/', $value) || strlen($value) % 4 === 1) {
            throw new \TypeError('bridge CryptoKey JWK uses canonical base64url');
        }
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if (!is_string($decoded) || rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $value) {
            throw new \TypeError('bridge CryptoKey JWK uses canonical base64url');
        }
        return $decoded;
    }

    /** @param array<string, mixed> $value @param list<string> $keys */
    private static function exactKeys(array $value, array $keys): void
    {
        $actual = array_keys($value);
        sort($actual);
        sort($keys);
        if ($actual !== $keys) {
            throw new \TypeError('bridge tagged value has an exact known shape');
        }
    }
}
