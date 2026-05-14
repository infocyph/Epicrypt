<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Infocyph\Epicrypt\Security\Support\AbstractPurposeToken;

final readonly class EmailVerificationToken extends AbstractPurposeToken
{
    protected const int DEFAULT_TTL_SECONDS = 86400;

    public function issue(string $userId, string $email): string
    {
        return $this->issueSubjectAndClaim(SecurityTokenPurpose::EMAIL_VERIFICATION, $userId, 'email', $email);
    }

    public function verify(string $token, ?string $email = null): bool
    {
        return $this->verifySubjectAndClaim(SecurityTokenPurpose::EMAIL_VERIFICATION, $token, null, 'email', $email);
    }
}
