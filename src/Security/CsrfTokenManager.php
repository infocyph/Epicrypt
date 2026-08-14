<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Psr\Clock\ClockInterface;

final readonly class CsrfTokenManager
{
    private SignedPayloadCodec $codec;

    public function __construct(
        #[\SensitiveParameter]
        string $secret,
        private int $ttlSeconds = 3600,
        private ClockInterface $clock = new SystemClock(),
    ) {
        SecurityPolicy::assertTtl($this->ttlSeconds, 86400, 'CSRF token TTL');
        $this->codec = new SignedPayloadCodec($secret, clock: $this->clock);
    }

    public function issueToken(string $sessionId): string
    {
        SecurityPolicy::assertIdentifier($sessionId, 'CSRF session ID');
        $purpose = SecurityTokenPurpose::CSRF->value;

        return $this->codec->issue([
            'sid' => $sessionId,
            'nonce' => bin2hex(random_bytes(16)),
        ], $this->clock->now()->getTimestamp() + $this->ttlSeconds, $purpose);
    }

    public function verifyToken(string $sessionId, #[\SensitiveParameter] string $token): bool
    {
        try {
            SecurityPolicy::assertIdentifier($sessionId, 'CSRF session ID');
            $claims = $this->codec->verify($token, SecurityTokenPurpose::CSRF->value);

            return isset($claims['sid']) && is_string($claims['sid']) && hash_equals($claims['sid'], $sessionId);
        } catch (\Throwable) {
            return false;
        }
    }
}
