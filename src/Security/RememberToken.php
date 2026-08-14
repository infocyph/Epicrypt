<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Infocyph\Epicrypt\Security\Support\AbstractPurposeToken;

final readonly class RememberToken extends AbstractPurposeToken
{
    protected const int DEFAULT_TTL_SECONDS = 1209600;

    protected const int MAX_TTL_SECONDS = 90 * 86400;

    public function issue(string $userId, string $deviceId): string
    {
        $this->assertIdentifier($userId, 'Remember-token user ID');
        $this->assertIdentifier($deviceId, 'Remember-token device ID');

        return $this->issueSubjectAndClaim(SecurityTokenPurpose::REMEMBER_TOKEN, $userId, 'device', $deviceId);
    }

    public function verify(#[\SensitiveParameter] string $token, string $userId, string $deviceId): bool
    {
        if (!$this->isValidIdentifier($userId, 'Remember-token user ID')
            || !$this->isValidIdentifier($deviceId, 'Remember-token device ID')) {
            return false;
        }

        return $this->verifySubjectAndClaim(SecurityTokenPurpose::REMEMBER_TOKEN, $token, $userId, 'device', $deviceId);
    }
}
