<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal\Clock;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * @internal
 */
final readonly class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
