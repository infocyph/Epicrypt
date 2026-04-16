<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;

/**
 * @internal
 */
final class LengthGuard
{
    public static function atLeast(int $length, int $minimum, string $label): void
    {
        if ($length < $minimum) {
            throw new ConfigurationException(sprintf('%s must be at least %d.', $label, $minimum));
        }
    }

    /**
     * @return int<1, max>
     */
    public static function atLeastOne(int $length, string $label): int
    {
        if ($length < 1) {
            throw new ConfigurationException(sprintf('%s must be at least %d.', $label, 1));
        }

        return $length;
    }
}
