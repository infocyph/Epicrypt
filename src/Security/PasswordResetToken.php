<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Infocyph\Epicrypt\Security\Support\AbstractPurposeToken;

final readonly class PasswordResetToken extends AbstractPurposeToken
{
    protected const int DEFAULT_TTL_SECONDS = 1800;

    protected const int MAX_TTL_SECONDS = 86400;

    public function issue(string $userId): string
    {
        $this->assertIdentifier($userId, 'Password-reset user ID');

        return $this->issueForPurpose(SecurityTokenPurpose::PASSWORD_RESET, [
            'sub' => $userId,
        ]);
    }

    public function verify(#[\SensitiveParameter] string $token, string $userId): bool
    {
        if (!$this->isValidIdentifier($userId, 'Password-reset user ID')) {
            return false;
        }

        return $this->verifyForPurpose(SecurityTokenPurpose::PASSWORD_RESET, $token, [
            'sub' => $userId,
        ]);
    }
}
