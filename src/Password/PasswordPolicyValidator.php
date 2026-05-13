<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;

final readonly class PasswordPolicyValidator
{
    public function __construct(
        private PasswordStrength $strength = new PasswordStrength(),
    ) {}

    public function validate(string $password, ?PasswordPolicy $policy = null): PasswordPolicyResult
    {
        $policy ??= new PasswordPolicy();
        $violations = [];

        if (strlen($password) < $policy->minLength) {
            $violations[] = 'too_short';
        }

        if ($policy->requireUpper && preg_match('/[A-Z]/', $password) !== 1) {
            $violations[] = 'missing_upper';
        }

        if ($policy->requireLower && preg_match('/[a-z]/', $password) !== 1) {
            $violations[] = 'missing_lower';
        }

        if ($policy->requireDigit && preg_match('/\d/', $password) !== 1) {
            $violations[] = 'missing_digit';
        }

        if ($policy->requireSymbol && preg_match('/[^a-zA-Z\d]/', $password) !== 1) {
            $violations[] = 'missing_symbol';
        }

        if (!$policy->includeAmbiguous && preg_match('/[Il]/', $password) === 1) {
            $violations[] = 'contains_ambiguous';
        }

        return new PasswordPolicyResult(
            valid: $violations === [],
            score: $this->strength->score($password),
            violations: $violations,
        );
    }
}
