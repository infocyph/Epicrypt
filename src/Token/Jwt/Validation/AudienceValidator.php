<?php

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;

final class AudienceValidator
{
    public function validate(string $expectedAudience, mixed $audience): void
    {
        if (is_array($audience)) {
            foreach ($audience as $item) {
                if (is_string($item) && hash_equals($expectedAudience, $item)) {
                    return;
                }
            }

            throw new InvalidClaimException('Invalid audience claim.');
        }

        if (! is_string($audience) || $audience === '' || ! hash_equals($expectedAudience, $audience)) {
            throw new InvalidClaimException('Invalid audience claim.');
        }
    }
}
