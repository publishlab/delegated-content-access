<?php

declare(strict_types=1);

namespace Dca\TestBridge\Value;

final class CryptoKeyValue
{
    /** @param array<string, mixed> $algorithm @param list<string> $usages */
    public function __construct(
        public readonly \OpenSSLAsymmetricKey $key,
        public readonly string $keyType,
        public readonly array $algorithm,
        public readonly bool $extractable,
        public readonly array $usages,
    ) {
    }
}
