<?php

namespace Infocyph\Epicrypt\Token\JWT\Validation;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;

final class ClaimValidator
{
    /**
     * @param array<string, mixed> $claims
     * @param array<int, string> $required
     */
    public function assertRequired(array $claims, array $required): void
    {
        foreach ($required as $claim) {
            if (! array_key_exists($claim, $claims)) {
                throw new InvalidClaimException('Missing claim: ' . $claim);
            }
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function assertStringClaim(array $claims, string $claim): void
    {
        if (! isset($claims[$claim]) || ! is_string($claims[$claim]) || $claims[$claim] === '') {
            throw new InvalidClaimException('Invalid claim: ' . $claim);
        }
    }
}
