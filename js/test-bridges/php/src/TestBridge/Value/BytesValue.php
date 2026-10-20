<?php

namespace Dca\TestBridge\Value;

final class BytesValue
{
    public function __construct(public readonly string $bytes)
    {
    }
}
