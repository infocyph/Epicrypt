<?php

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class Assert
{
    public static function nonEmptyString(mixed $value, string $name): string
    {
        if (! is_string($value) || $value === '') {
            throw new ConfigurationException(sprintf('%s must be a non-empty string.', $name));
        }

        return $value;
    }
}
