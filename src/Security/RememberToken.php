<?php

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;

final readonly class RememberToken
{
    private SignedPayloadCodec $codec;

    public function __construct(
        string $secret,
        private int $ttlSeconds = 1209600,
    ) {
        $this->codec = new SignedPayloadCodec($secret);
    }

    public function issue(string $userId, string $deviceId): string
    {
        $purpose = SecurityTokenPurpose::REMEMBER_TOKEN->value;

        return $this->codec->issue([
            'sub' => $userId,
            'device' => $deviceId,
            'purpose' => $purpose,
        ], time() + $this->ttlSeconds, $purpose);
    }

    public function verify(string $token, ?string $userId = null, ?string $deviceId = null): bool
    {
        try {
            $purpose = SecurityTokenPurpose::REMEMBER_TOKEN->value;
            $claims = $this->codec->verify($token, $purpose);
            if (($claims['purpose'] ?? null) !== $purpose) {
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
