<?php

declare(strict_types=1);

namespace Dca\TestBridge\Value;

/**
 * A list the port declared as one through a return type marker, so an empty
 * one stays a list whatever the reference type says.
 */
final class ListValue
{
    /** @param list<mixed> $entries */
    public function __construct(public readonly array $entries)
    {
    }
}
