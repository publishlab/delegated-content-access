<?php

declare(strict_types=1);

namespace Dca\Porting;

/**
 * Names the reference export a method or exception class implements, when it
 * differs from the method's own name, such as `inspectPeriodGeometryBounds`.
 */
#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD)]
final class SourceExport
{
    public function __construct(public readonly string $name)
    {
    }
}
