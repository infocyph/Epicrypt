<?php

namespace Infocyph\Epicrypt\Password\Generator;

final readonly class PasswordPolicy
{
    public function __construct(
        public int $minLength = 12,
        public bool $requireUpper = true,
        public bool $requireLower = true,
        public bool $requireDigit = true,
        public bool $requireSymbol = true,
        public bool $includeAmbiguous = false,
    ) {}
}
