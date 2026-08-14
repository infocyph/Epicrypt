<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Infocyph\Epicrypt\Security\Support\AbstractPurposeToken;

final readonly class EmailVerificationToken extends AbstractPurposeToken
{
    protected const int DEFAULT_TTL_SECONDS = 86400;

    protected const int MAX_TTL_SECONDS = 7 * 86400;

    public function issue(string $userId, string $email): string
    {
        $this->assertIdentifier($userId, 'Email-verification user ID');
        $this->assertEmail($email);

        return $this->issueSubjectAndClaim(SecurityTokenPurpose::EMAIL_VERIFICATION, $userId, 'email', $email);
    }

    public function verify(#[\SensitiveParameter] string $token, string $userId, string $email): bool
    {
        if (!$this->isValidIdentifier($userId, 'Email-verification user ID') || !$this->isValidEmail($email)) {
            return false;
        }

        return $this->verifySubjectAndClaim(SecurityTokenPurpose::EMAIL_VERIFICATION, $token, $userId, 'email', $email);
    }

    private function assertEmail(string $email): void
    {
        $this->assertIdentifier($email, 'Email-verification email');
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new \Infocyph\Epicrypt\Exception\ConfigurationException('Email-verification email is invalid.');
        }
    }

    private function isValidEmail(string $email): bool
    {
        try {
            $this->assertEmail($email);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }
}
