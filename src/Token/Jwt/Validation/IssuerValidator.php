<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;

final class IssuerValidator
{
    public function validate(string $expectedIssuer, mixed $issuer): void
    {
        if (!is_string($issuer) || $issuer === '' || !hash_equals($expectedIssuer, $issuer)) {
            throw new InvalidClaimException('Invalid issuer claim.');
        }
    }
}
