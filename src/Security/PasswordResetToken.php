<?php

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;

final readonly class PasswordResetToken
{
    private SignedPayloadCodec $codec;

    public function __construct(
        string $secret,
        private int $ttlSeconds = 1800,
    ) {
        $this->codec = new SignedPayloadCodec($secret);
    }

    public function issue(string $userId): string
    {
        return $this->codec->issue([
            'sub' => $userId,
            'purpose' => 'password_reset',
        ], time() + $this->ttlSeconds, 'password_reset');
    }

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
