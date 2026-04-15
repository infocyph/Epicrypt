<?php

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Contract\CsrfTokenManagerInterface;
use Infocyph\Epicrypt\Exception\Token\TokenException;

final readonly class CsrfTokenManager implements CsrfTokenManagerInterface
{
    public function __construct(
        private SignedPayloadCodec $codec,
        private int $ttlSeconds = 3600,
    ) {}

    public function issueToken(string $sessionId): string
    {
        return $this->codec->issue([
            'sid' => $sessionId,
            'nonce' => bin2hex(random_bytes(16)),
        ], time() + $this->ttlSeconds, 'csrf');
    }

    public function verifyToken(string $sessionId, string $token): bool
    {
        try {
            $claims = $this->codec->verify($token, 'csrf');

            return isset($claims['sid']) && is_string($claims['sid']) && hash_equals($claims['sid'], $sessionId);
        } catch (TokenException) {
            return false;
        }
    }
}
