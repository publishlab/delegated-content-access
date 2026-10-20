<?php

declare(strict_types=1);

namespace BridgeValues;

use Dca\Porting\Bytes;
use Dca\TestBridge\Value\UndefinedValue;

/**
 * The native fixture for the bridge-values suite. The suite and its expected
 * values are in ../../../_shared/bridge-values/; suite.mjs there defines what
 * each method returns. Its mixed parameters receive distinct text strings and
 * byte objects, including inside stdClass records.
 */
#[\Dca\Porting\SourceModule('values.js')]
final class Values
{
    public static function identity(mixed $value): mixed
    {
        return $value;
    }

    public static function inspect(mixed $value): mixed
    {
        if ($value === null || is_bool($value) || is_int($value) || is_float($value)) {
            return $value;
        }
        if (is_string($value)) {
            return (object) ['octets' => bin2hex($value)];
        }
        if ($value instanceof Bytes) {
            return (object) ['octets' => bin2hex($value->bytes)];
        }
        if ($value instanceof UndefinedValue) {
            return (object) ['undefined' => true];
        }
        if ($value instanceof \DateTimeInterface) {
            return (object) ['epochMilliseconds' => $value->getTimestamp() * 1000 + intdiv((int) $value->format('u'), 1000)];
        }
        if (is_array($value)) {
            return array_map([self::class, 'inspect'], $value);
        }
        if ($value instanceof \stdClass) {
            return self::members($value, [self::class, 'inspect']);
        }
        throw new \TypeError('fixture value has no bridge value type');
    }

    public static function transform(mixed $value): mixed
    {
        if ($value === null || $value instanceof UndefinedValue) {
            return $value;
        }
        if (is_bool($value)) {
            return !$value;
        }
        if (is_int($value) || is_float($value)) {
            return -$value;
        }
        if (is_string($value)) {
            return $value . "\u{e9}";
        }
        if ($value instanceof Bytes) {
            return new Bytes($value->bytes . "\xff");
        }
        if ($value instanceof \DateTimeInterface) {
            return \DateTimeImmutable::createFromInterface($value)->modify('+1 millisecond');
        }
        if (is_array($value)) {
            return array_reverse(array_map([self::class, 'transform'], $value));
        }
        if ($value instanceof \stdClass) {
            return self::members($value, [self::class, 'transform']);
        }
        throw new \TypeError('fixture value has no bridge value type');
    }

    private static function members(\stdClass $record, callable $each): \stdClass
    {
        $result = new \stdClass();
        foreach (get_object_vars($record) as $name => $member) {
            $result->{(string) $name} = $each($member);
        }
        return $result;
    }
}
