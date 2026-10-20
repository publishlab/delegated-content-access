<?php

declare(strict_types=1);

namespace Dca\TestBridge;

/**
 * A refusal of the bridge itself: a handle this session did not issue, or a
 * receiver that does not fit the member. It answers as an adapter refusal and
 * never reaches the test target.
 */
final class HandleRefusal extends \RuntimeException
{
}
