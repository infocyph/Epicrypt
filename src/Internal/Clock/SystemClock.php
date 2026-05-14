<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal\Clock;

/**
 * @internal
 */
final readonly class SystemClock implements ClockInterface
{
    public function now(): int
    {
        return time();
    }
}
