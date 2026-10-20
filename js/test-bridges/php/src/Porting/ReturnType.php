<?php

declare(strict_types=1);

namespace Dca\Porting;

/**
 * Names the bridge value type of a method's return where the PHP value is
 * ambiguous: `Uint8Array` for a byte string, `record` or `list` for an array,
 * `['Uint8Array']` for a list whose every entry is bytes, or member names mapped
 * to those forms for a record, such as `['key' => 'Uint8Array', 'items' => 'list']`.
 */
#[\Attribute(\Attribute::TARGET_METHOD)]
final class ReturnType
{
    /** @param string|array<mixed> $name */
    public function __construct(public readonly string|array $name)
    {
    }
}
