<?php

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;

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
        $purpose = SecurityTokenPurpose::PASSWORD_RESET->value;

        return $this->codec->issue([
            'sub' => $userId,
            'purpose' => $purpose,
        ], time() + $this->ttlSeconds, $purpose);
    }

    public function verify(string $token, ?string $userId = null): bool
    {
        try {
            $purpose = SecurityTokenPurpose::PASSWORD_RESET->value;
            $claims = $this->codec->verify($token, $purpose);
            if (($claims['purpose'] ?? null) !== $purpose) {
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
