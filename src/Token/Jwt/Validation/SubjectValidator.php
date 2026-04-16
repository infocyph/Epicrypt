<?php

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;

final class SubjectValidator
{
    public function validate(string $expectedSubject, mixed $subject): void
    {
        if (! is_string($subject) || $subject === '' || ! hash_equals($expectedSubject, $subject)) {
            throw new InvalidClaimException('Invalid subject claim.');
        }
    }
}
