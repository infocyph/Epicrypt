<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Generator;

use Infocyph\Epicrypt\Exception\Password\InvalidPasswordException;

final readonly class PasswordPolicy
{
    public const string AMBIGUOUS_CHARACTERS = '0O1IlL';

    public function __construct(
        public int $minLength = 12,
        public bool $requireUpper = true,
        public bool $requireLower = true,
        public bool $requireDigit = true,
        public bool $requireSymbol = true,
        public bool $includeAmbiguous = false,
    ) {
        if ($this->minLength < 1) {
            throw new InvalidPasswordException('Password minimum length must be positive.');
        }
    }

    public function requiredCharacterClasses(): int
    {
        return (int) $this->requireUpper
            + (int) $this->requireLower
            + (int) $this->requireDigit
            + (int) $this->requireSymbol;
    }
}
