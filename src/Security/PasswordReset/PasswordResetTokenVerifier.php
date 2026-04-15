<?php

namespace Infocyph\Epicrypt\Security\PasswordReset;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

final readonly class PasswordResetTokenVerifier
{
    public function __construct(
        private SignedPayloadCodec $codec,
    ) {}

    public function verify(string $token, ?string $userId = null): bool
    {
        try {
            $claims = $this->codec->verify($token, 'password_reset');

            if (($claims['purpose'] ?? null) !== 'password_reset') {
                return false;
            }

            if ($userId !== null) {
                return isset($claims['sub']) && is_string($claims['sub']) && hash_equals($claims['sub'], $userId);
            }

            return true;
        } catch (TokenException) {
            return false;
        }
    }
}
