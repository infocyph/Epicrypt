<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Integrity\Support;

use Infocyph\Epicrypt\Internal\SecureCompare;

/**
 * @internal
 */
final class TimingSafeComparator
{
    public function equals(string $known, string $given): bool
    {
        return SecureCompare::equals($known, $given);
    }
}
