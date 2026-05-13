<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

final readonly class PasswordPolicyResult
{
    /**
     * @param list<string> $violations
     */
    public function __construct(
        public bool $valid,
        public int $score,
        public array $violations = [],
    ) {}
}
