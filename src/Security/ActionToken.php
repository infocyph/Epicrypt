<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Infocyph\Epicrypt\Security\Support\AbstractPurposeToken;

final readonly class ActionToken extends AbstractPurposeToken
{
    protected const int DEFAULT_TTL_SECONDS = 900;

    protected const int MAX_TTL_SECONDS = 3600;

    /**
     * @param array<string, scalar> $metadata
     */
    public function issue(string $subject, string $action, array $metadata = []): string
    {
        $this->assertIdentifier($subject, 'Action-token subject');
        $this->assertIdentifier($action, 'Action-token action');

        return $this->issueForPurpose(SecurityTokenPurpose::ACTION_TOKEN, [
            'sub' => $subject,
            'action' => $action,
            'ctx' => $metadata,
        ]);
    }

    public function verify(#[\SensitiveParameter] string $token, string $subject, string $action): bool
    {
        if (!$this->isValidIdentifier($subject, 'Action-token subject')
            || !$this->isValidIdentifier($action, 'Action-token action')) {
            return false;
        }

        return $this->verifyForPurpose(SecurityTokenPurpose::ACTION_TOKEN, $token, [
            'sub' => $subject,
            'action' => $action,
        ]);
    }
}
