<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Infocyph\Epicrypt\Security\Support\AbstractPurposeToken;

final readonly class ActionToken extends AbstractPurposeToken
{
    protected const int DEFAULT_TTL_SECONDS = 900;

    /**
     * @param array<string, scalar> $context
     */
    public function issue(string $subject, string $action, array $context = []): string
    {
        return $this->issueForPurpose(SecurityTokenPurpose::ACTION_TOKEN, [
            'sub' => $subject,
            'action' => $action,
            'ctx' => $context,
        ]);
    }

    public function verify(string $token, ?string $subject = null, ?string $action = null): bool
    {
        return $this->verifyForPurpose(SecurityTokenPurpose::ACTION_TOKEN, $token, [
            'sub' => $subject,
            'action' => $action,
        ]);
    }
}
