<?php

namespace Infocyph\Epicrypt\Security\EmailVerification;

use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

final readonly class EmailVerificationTokenIssuer
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
}
