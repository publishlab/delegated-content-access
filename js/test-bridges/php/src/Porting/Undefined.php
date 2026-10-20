<?php

declare(strict_types=1);

namespace Dca\Porting;

/**
 * JavaScript `undefined`, which PHP lacks. A port returns `new Undefined()`
 * where it means `undefined`, at the top level or inside a record or list.
 * A plain `null` crosses as `null`, except where the reference type admits
 * `undefined` and not `null`: there the driver reads it as `undefined`.
 */
final class Undefined
{
}
