<?php

declare(strict_types=1);

namespace Dca\Porting;

/**
 * An octet sequence that crosses the bridge as a JavaScript `Uint8Array`. A
 * plain PHP string may cross as text, so a port can return bytes as
 * `new Bytes($raw)`. A parameter declared `mixed` receives this class for
 * byte inputs; a `string` parameter receives the raw octets.
 */
final class Bytes implements \Stringable
{
    public function __construct(public readonly string $bytes)
    {
    }

    public function __toString(): string
    {
        return $this->bytes;
    }
}
