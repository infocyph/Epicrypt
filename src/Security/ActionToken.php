<?php

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\TokenException;

final readonly class ActionToken
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

    public function verify(string $token, ?string $subject = null, ?string $action = null): bool
    {
        try {
            $claims = $this->codec->verify($token, 'action_token');
            if (($claims['purpose'] ?? null) !== 'action_token') {
                return false;
            }

            if ($subject !== null && (! isset($claims['sub']) || ! is_string($claims['sub']) || ! hash_equals($claims['sub'], $subject))) {
                return false;
            }

            if ($action !== null && (! isset($claims['action']) || ! is_string($claims['action']) || ! hash_equals($claims['action'], $action))) {
                return false;
            }

            return true;
        } catch (TokenException) {
            return false;
        }
    }
}
