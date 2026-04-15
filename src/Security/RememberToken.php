<?php

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\TokenException;

final readonly class RememberToken
{
    public function __construct(
        private SignedPayloadCodec $codec,
        private int $ttlSeconds = 1209600,
    ) {}

    public function issue(string $userId, string $deviceId): string
    {
        return $this->codec->issue([
            'sub' => $userId,
            'device' => $deviceId,
            'purpose' => 'remember_token',
        ], time() + $this->ttlSeconds, 'remember_token');
    }

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
