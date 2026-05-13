<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;

final readonly class ExpirationValidator
{
    public function __construct(
        private int $leeway = 0,
        private ?int $maxTokenAgeSeconds = null,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function validate(mixed $notBefore, mixed $expiresAt, mixed $issuedAt = null): void
    {
        if (!is_numeric($notBefore) || !is_numeric($expiresAt)) {
            throw new InvalidClaimException('Claims "nbf" and "exp" must be numeric timestamps.');
        }

        $now = $this->clock->now();
        if ($now + $this->leeway < (int) $notBefore) {
            throw new InvalidClaimException('Token is not active yet.');
        }

        if ($now - $this->leeway > (int) $expiresAt) {
            throw new ExpiredTokenException('Token has expired.');
        }

        if ($this->maxTokenAgeSeconds !== null) {
            if (!is_numeric($issuedAt)) {
                throw new InvalidClaimException('Claim "iat" must be numeric when max token age is enforced.');
            }

            if ($now - (int) $issuedAt > $this->maxTokenAgeSeconds + $this->leeway) {
                throw new ExpiredTokenException('Token exceeded the maximum allowed age.');
            }
        }
    }
}
