<?php

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
}
