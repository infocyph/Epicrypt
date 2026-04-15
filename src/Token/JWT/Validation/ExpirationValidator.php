<?php

namespace Infocyph\Epicrypt\Token\JWT\Validation;

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;

final readonly class ExpirationValidator
{
    public function __construct(
        private int $leeway = 0,
    ) {}

    public function validate(mixed $notBefore, mixed $expiresAt): void
    {
        if (! is_numeric($notBefore) || ! is_numeric($expiresAt)) {
            throw new InvalidClaimException('Claims "nbf" and "exp" must be numeric timestamps.');
        }

        $now = time();
        if ($now + $this->leeway < (int) $notBefore) {
            throw new InvalidClaimException('Token is not active yet.');
        }

        if ($now - $this->leeway > (int) $expiresAt) {
            throw new ExpiredTokenException('Token has expired.');
        }
    }
}
