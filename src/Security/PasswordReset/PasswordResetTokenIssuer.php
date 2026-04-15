<?php

namespace Infocyph\Epicrypt\Security\PasswordReset;

use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

final readonly class PasswordResetTokenIssuer
{
    public function __construct(
        private SignedPayloadCodec $codec,
        private int $ttlSeconds = 1800,
    ) {}

    public function issue(string $userId): string
    {
        return $this->codec->issue([
            'sub' => $userId,
            'purpose' => 'password_reset',
        ], time() + $this->ttlSeconds, 'password_reset');
    }
}
