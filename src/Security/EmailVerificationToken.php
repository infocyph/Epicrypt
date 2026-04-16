<?php

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;

final readonly class EmailVerificationToken
{
    private SignedPayloadCodec $codec;

    public function __construct(
        string $secret,
        private int $ttlSeconds = 86400,
    ) {
        $this->codec = new SignedPayloadCodec($secret);
    }

    public function issue(string $userId, string $email): string
    {
        $purpose = SecurityTokenPurpose::EMAIL_VERIFICATION->value;

        return $this->codec->issue([
            'sub' => $userId,
            'email' => $email,
            'purpose' => $purpose,
        ], time() + $this->ttlSeconds, $purpose);
    }

    public function verify(string $token, ?string $email = null): bool
    {
        try {
            $purpose = SecurityTokenPurpose::EMAIL_VERIFICATION->value;
            $claims = $this->codec->verify($token, $purpose);
            if (($claims['purpose'] ?? null) !== $purpose) {
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
