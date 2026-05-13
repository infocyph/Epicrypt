<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Infocyph\Epicrypt\Security\Support\AbstractPurposeToken;

final readonly class ActionToken extends AbstractPurposeToken
{
    public function __construct(
        string $secret,
        int $ttlSeconds = 900,
        ClockInterface $clock = new SystemClock(),
    ) {
        parent::__construct($secret, $ttlSeconds, $clock);
    }

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
