<?php

declare(strict_types=1);

namespace Dca\Porting;

/**
 * Names the JavaScript reference module a class implements, as a path below the
 * reference root, such as `core-issuer/IssuerEngine.js`.
 */
#[\Attribute(\Attribute::TARGET_CLASS)]
final class SourceModule
{
    public function __construct(public readonly string $path)
    {
    }
}
