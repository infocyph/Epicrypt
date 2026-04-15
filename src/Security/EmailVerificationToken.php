<?php

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\TokenException;

final readonly class EmailVerificationToken
{
    public function __construct(
        private SignedPayloadCodec $codec,
        private int $ttlSeconds = 86400,
    ) {}

    public function issue(string $userId, string $email): string
    {
        return $this->codec->issue([
            'sub' => $userId,
            'email' => $email,
            'purpose' => 'email_verification',
        ], time() + $this->ttlSeconds, 'email_verification');
    }

    public function verify(string $token, ?string $email = null): bool
    {
        try {
            $claims = $this->codec->verify($token, 'email_verification');
            if (($claims['purpose'] ?? null) !== 'email_verification') {
                return false;
            }

            if ($email !== null) {
                return isset($claims['email']) && is_string($claims['email']) && hash_equals($claims['email'], $email);
            }

            return true;
        } catch (TokenException) {
            return false;
        }
    }
}
