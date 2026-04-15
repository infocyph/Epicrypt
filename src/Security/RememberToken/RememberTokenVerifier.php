<?php

namespace Infocyph\Epicrypt\Security\RememberToken;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

final readonly class RememberTokenVerifier
{
    public function __construct(
        private SignedPayloadCodec $codec,
    ) {}

    public function verify(string $token, ?string $userId = null, ?string $deviceId = null): bool
    {
        try {
            $claims = $this->codec->verify($token, 'remember_token');
            if (($claims['purpose'] ?? null) !== 'remember_token') {
                return false;
            }

            if ($userId !== null && (! isset($claims['sub']) || ! is_string($claims['sub']) || ! hash_equals($claims['sub'], $userId))) {
                return false;
            }

            if ($deviceId !== null && (! isset($claims['device']) || ! is_string($claims['device']) || ! hash_equals($claims['device'], $deviceId))) {
                return false;
            }

            return true;
        } catch (TokenException) {
            return false;
        }
    }
}
