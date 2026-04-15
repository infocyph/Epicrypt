<?php

namespace Infocyph\Epicrypt\Security\RememberToken;

use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

final readonly class RememberTokenIssuer
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
}
