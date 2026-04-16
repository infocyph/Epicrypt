<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\Contract\CsrfTokenManagerInterface;
use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;

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
        $purpose = SecurityTokenPurpose::CSRF->value;

        return $this->codec->issue([
            'sid' => $sessionId,
            'nonce' => bin2hex(random_bytes(16)),
        ], time() + $this->ttlSeconds, $purpose);
    }

    public function verifyToken(string $sessionId, string $token): bool
    {
        try {
            $claims = $this->codec->verify($token, SecurityTokenPurpose::CSRF->value);

            return isset($claims['sid']) && is_string($claims['sid']) && hash_equals($claims['sid'], $sessionId);
        } catch (TokenException) {
            return false;
        }
    }
}
