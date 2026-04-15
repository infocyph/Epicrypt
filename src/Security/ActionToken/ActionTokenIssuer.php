<?php

namespace Infocyph\Epicrypt\Security\ActionToken;

use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

final readonly class ActionTokenIssuer
{
    public function __construct(
        private SignedPayloadCodec $codec,
        private int $ttlSeconds = 900,
    ) {}

    /**
     * @param array<string, scalar> $context
     */
    public function issue(string $subject, string $action, array $context = []): string
    {
        return $this->codec->issue([
            'sub' => $subject,
            'action' => $action,
            'ctx' => $context,
            'purpose' => 'action_token',
        ], time() + $this->ttlSeconds, 'action_token');
    }
}
