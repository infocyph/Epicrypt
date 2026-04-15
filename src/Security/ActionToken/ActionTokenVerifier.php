<?php

namespace Infocyph\Epicrypt\Security\ActionToken;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

final readonly class ActionTokenVerifier
{
    public function __construct(
        private SignedPayloadCodec $codec,
    ) {}

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
