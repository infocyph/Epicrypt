<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal\Clock;

/**
 * @internal
 */
interface ClockInterface
{
    public function now(): int;
}
