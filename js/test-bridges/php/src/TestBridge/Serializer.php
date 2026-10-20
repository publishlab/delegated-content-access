<?php

declare(strict_types=1);

namespace Dca\TestBridge;

use Dca\TestBridge\Value\BytesValue;
use Dca\TestBridge\Value\CryptoKeyValue;
use Dca\TestBridge\Value\ListValue;
use Dca\TestBridge\Value\UndefinedValue;

final class Serializer
{
    /**
     * `$bytesClass` marks returned bytes and explicitly ambiguous inputs.
     * `$undefinedClass` is the class a port returns to send `undefined`.
     * `$handles` carries objects of claimed classes; without it no handle
     * crosses.
     */
    public function __construct(
        private readonly string $bytesClass = 'Dca\\Porting\\Bytes',
        private readonly string $undefinedClass = 'Dca\\Porting\\Undefined',
        private readonly ?HandleTable $handles = null,
    ) {
        if (!class_exists($bytesClass) || !is_subclass_of($bytesClass, \Stringable::class)) {
            throw new \InvalidArgumentException('DCA_PHP_BYTES_CLASS names a class built from one string and read with __toString, such as Dca\\Porting\\Bytes');
        }
        if (!class_exists($undefinedClass)) {
            throw new \InvalidArgumentException('DCA_PHP_UNDEFINED_CLASS names a class that loads, such as Dca\\Porting\\Undefined');
        }
    }

    /**
     * `CryptoKey` is absent: every PHP member is `sync`, the driver's synchronous
     * call cannot serialize a key, and `encode` cannot return one.
     *
     * @return list<string>
     */
    public function valueTypes(): array
    {
        return ['null', 'boolean', 'string', 'number', 'record', 'list', 'undefined', 'Uint8Array', 'Date'];
    }

    /**
     * A driver record becomes `stdClass` and a list becomes a list array.
     * Bytes remain private markers until target parameter types are known.
     */
    public function decode(mixed $value): mixed
    {
        if ($value instanceof \stdClass) {
            $record = get_object_vars($value);
            if (array_key_exists('$type', $record)) {
                return $this->decodeTagged($record);
            }
            return $this->decodeRecord($record);
        }
        if (!is_array($value)) {
            if (is_float($value) && !is_finite($value)) {
                throw new \TypeError('bridge numbers are finite');
            }
            return $value;
        }
        if (!array_is_list($value)) {
            throw new \TypeError('bridge JSON records remain objects');
        }
        return array_map(fn (mixed $entry): mixed => $this->decode($entry), $value);
    }

    /**
     * Encodes a value the adapter builds, such as a description.
     */
    public function encode(mixed $value): mixed
    {
        $declared = [];
        return $this->encodeAt($value, [], $declared);
    }

    /**
     * Encodes what a test target returned, and lists where its PHP type says
     * the JavaScript type: `stdClass`, an associative array and a record marker
     * say record; a list array with entries and a list marker say list; the
     * bytes class and a bytes marker say `Uint8Array`. `[]`, a string and
     * `null` say nothing: the driver reads them by the reference type. A string
     * that is not UTF-8 cannot be JSON text, so it goes out as bytes, still
     * undeclared.
     *
     * @return array{0: mixed, 1: list<array{at: list<string|int>, type: string}>}
     */
    public function encodeAnswer(mixed $value): array
    {
        $declared = [];
        $encoded = $this->encodeAt($value, [], $declared);
        return [$encoded, $declared];
    }

    /**
     * @param list<string|int> $at the position of `$value` in the answer
     * @param list<array{at: list<string|int>, type: string}> $declared
     */
    private function encodeAt(mixed $value, array $at, array &$declared): mixed
    {
        if ($value instanceof UndefinedValue || $value instanceof $this->undefinedClass) {
            return ['$type' => 'undefined'];
        }
        if ($value instanceof BytesValue) {
            $declared[] = ['at' => $at, 'type' => 'Uint8Array'];
            return self::bytes($value->bytes);
        }
        if ($value instanceof $this->bytesClass) {
            $declared[] = ['at' => $at, 'type' => 'Uint8Array'];
            return self::bytes((string) $value);
        }
        if ($value instanceof ListValue) {
            $declared[] = ['at' => $at, 'type' => 'list'];
            return $this->encodeList($value->entries, $at, $declared);
        }
        if ($value instanceof \DateTimeInterface) {
            // Rebuilding from `U.u` would move a pre-1970 instant:
            // 1969-12-31T23:59:59.998Z formats as -1.998000 and reads back as 23:59:58.002Z.
            $utc = \DateTimeImmutable::createFromInterface($value)->setTimezone(new \DateTimeZone('UTC'));
            return (object) ['$type' => 'Date', 'iso' => $utc->format('Y-m-d\\TH:i:s.v\\Z')];
        }
        if ($value instanceof CryptoKeyValue) {
            throw new \TypeError('bridge does not expose native CryptoKey material');
        }
        if ($value instanceof \stdClass) {
            $declared[] = ['at' => $at, 'type' => 'record'];
            return $this->encodeRecord(get_object_vars($value), $at, $declared);
        }
        if (is_object($value)) {
            $tag = $this->handles?->tag($value);
            if ($tag !== null) {
                return $tag;
            }
            throw new \TypeError('bridge carries stdClass records, list arrays, bytes, instants, scalars and objects of claimed classes, not ' . get_class($value));
        }
        if (is_string($value) && preg_match('//u', $value) !== 1) {
            return self::bytes($value);
        }
        if (!is_array($value)) {
            if (is_float($value) && !is_finite($value)) {
                throw new \TypeError('bridge numbers are finite');
            }
            return $value;
        }
        if (array_is_list($value)) {
            if ($value !== []) {
                $declared[] = ['at' => $at, 'type' => 'list'];
            }
            return $this->encodeList($value, $at, $declared);
        }
        foreach (array_keys($value) as $key) {
            if (is_int($key)) {
                throw new \TypeError('bridge JSON record keys are not integer-like; return a stdClass record');
            }
        }
        $declared[] = ['at' => $at, 'type' => 'record'];
        return $this->encodeRecord($value, $at, $declared);
    }

    /**
     * @param list<mixed> $entries @param list<string|int> $at
     * @param list<array{at: list<string|int>, type: string}> $declared
     * @return list<mixed>
     */
    private function encodeList(array $entries, array $at, array &$declared): array
    {
        $list = [];
        foreach ($entries as $index => $entry) {
            $list[] = $this->encodeAt($entry, [...$at, $index], $declared);
        }
        return $list;
    }

    /**
     * @param array<array-key, mixed> $members @param list<string|int> $at
     * @param list<array{at: list<string|int>, type: string}> $declared
     */
    private function encodeRecord(array $members, array $at, array &$declared): \stdClass
    {
        $record = new \stdClass();
        foreach ($members as $name => $entry) {
            $record->{(string) $name} = $this->encodeAt($entry, [...$at, (string) $name], $declared);
        }
        if (array_key_exists('$type', $members)) {
            return (object) ['$type' => 'Record', 'value' => $record];
        }
        return $record;
    }

    private static function bytes(string $bytes): array
    {
        return ['$type' => 'Uint8Array', 'base64url' => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=')];
    }

    /** @param array<string, mixed> $value */
    private function decodeTagged(array $value): mixed
    {
        if ($value === ['$type' => 'undefined']) {
            return new UndefinedValue();
        }
        if (($value['$type'] ?? null) === 'Uint8Array' && self::hasExactKeys($value, ['$type', 'base64url']) && is_string($value['base64url'])) {
            return new BytesValue($this->base64url($value['base64url']));
        }
        if (($value['$type'] ?? null) === 'Date' && self::hasExactKeys($value, ['$type', 'iso']) && is_string($value['iso'])) {
            $date = \DateTimeImmutable::createFromFormat('Y-m-d\\TH:i:s.v\\Z', $value['iso'], new \DateTimeZone('UTC'));
            if (!$date || $date->format('Y-m-d\\TH:i:s.v\\Z') !== $value['iso']) {
                throw new \TypeError('bridge instant is canonical ISO time');
            }
            return $date;
        }
        if (($value['$type'] ?? null) === 'Record' && self::hasExactKeys($value, ['$type', 'value']) && $value['value'] instanceof \stdClass) {
            return $this->decodeRecord(get_object_vars($value['value']));
        }
        if (($value['$type'] ?? null) === 'CryptoKey') {
            return SerializerCryptoKey::decode($value);
        }
        if (($value['$type'] ?? null) === 'Handle') {
            return $this->decodeHandle($value);
        }
        throw new \TypeError('bridge tagged value has an exact known shape');
    }

    /**
     * The object a handle names in this session. Only the exact handle layout
     * is a handle; an ordinary record with the same members arrives escaped.
     *
     * @param array<string, mixed> $value
     */
    private function decodeHandle(array $value): object
    {
        $class = $value['class'] ?? null;
        $handle = $value['handle'] ?? null;
        $exact = self::hasExactKeys($value, ['$type', 'class', 'handle']);
        $named = is_string($class) && $class !== '';
        $issued = is_string($handle) && $handle !== '';
        if (!$exact || !$named || !$issued) {
            throw new \TypeError('bridge tagged value has an exact known shape');
        }
        if ($this->handles === null) {
            throw new HandleRefusal('bridge handle needs its session');
        }
        return $this->handles->resolve($class, $handle);
    }

    /** @param array<array-key, mixed> $value */
    private function decodeRecord(array $value): \stdClass
    {
        $record = new \stdClass();
        foreach ($value as $key => $entry) {
            $record->{(string) $key} = $this->decode($entry);
        }
        return $record;
    }

    private function base64url(string $value): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]*$/', $value) || strlen($value) % 4 === 1) {
            throw new \TypeError('bridge bytes are canonical base64url');
        }
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if (!is_string($decoded) || rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $value) {
            throw new \TypeError('bridge bytes are canonical base64url');
        }
        return $decoded;
    }

    /** @param array<string, mixed> $value @param list<string> $keys */
    private static function hasExactKeys(array $value, array $keys): bool
    {
        $actual = array_keys($value);
        sort($actual);
        sort($keys);
        return $actual === $keys;
    }
}
