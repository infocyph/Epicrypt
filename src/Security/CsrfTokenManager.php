<?php

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Contract\CsrfTokenManagerInterface;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;

final readonly class CsrfTokenManager implements CsrfTokenManagerInterface
{
    private SignedPayloadCodec $codec;

    public function __construct(
        string $secret,
        private int $ttlSeconds = 3600,
    ) {
        $this->codec = new SignedPayloadCodec($secret);
    }

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
