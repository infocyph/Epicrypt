<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Infocyph\Epicrypt\Security\Support\AbstractPurposeToken;

final readonly class PasswordResetToken extends AbstractPurposeToken
{
    public function __construct(
        string $secret,
        int $ttlSeconds = 1800,
    ) {
        parent::__construct($secret, $ttlSeconds);
    }

    public function issue(string $userId): string
    {
        return $this->issueForPurpose(SecurityTokenPurpose::PASSWORD_RESET, [
            'sub' => $userId,
        ]);
    }

    public function verify(string $token, ?string $userId = null): bool
    {
        return $this->verifyForPurpose(SecurityTokenPurpose::PASSWORD_RESET, $token, [
            'sub' => $userId,
        ]);
    }
}
