<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Infocyph\Epicrypt\Security\Support\AbstractPurposeToken;

final readonly class RememberToken extends AbstractPurposeToken
{
    public function __construct(
        string $secret,
        int $ttlSeconds = 1209600,
    ) {
        parent::__construct($secret, $ttlSeconds);
    }

    public function issue(string $userId, string $deviceId): string
    {
        return $this->issueSubjectAndClaim(SecurityTokenPurpose::REMEMBER_TOKEN, $userId, 'device', $deviceId);
    }

    public function verify(string $token, ?string $userId = null, ?string $deviceId = null): bool
    {
        return $this->verifySubjectAndClaim(SecurityTokenPurpose::REMEMBER_TOKEN, $token, $userId, 'device', $deviceId);
    }
}
