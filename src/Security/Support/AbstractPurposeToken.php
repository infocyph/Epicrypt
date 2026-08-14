<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security\Support;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;
use Psr\Clock\ClockInterface;

abstract readonly class AbstractPurposeToken
{
    protected const int DEFAULT_TTL_SECONDS = 3600;

    protected const int MAX_TTL_SECONDS = 86400;

    protected int $ttlSeconds;

    private SignedPayloadCodec $codec;

    public function __construct(
        #[\SensitiveParameter]
        string $secret,
        ?int $ttlSeconds = null,
        protected ClockInterface $clock = new SystemClock(),
    ) {
        $this->ttlSeconds = $ttlSeconds ?? static::DEFAULT_TTL_SECONDS;
        SecurityPolicy::assertTtl($this->ttlSeconds, static::MAX_TTL_SECONDS, 'Security token TTL');
        $this->codec = new SignedPayloadCodec($secret, clock: $this->clock);
    }

    protected function assertIdentifier(string $value, string $label): void
    {
        SecurityPolicy::assertIdentifier($value, $label);
    }

    /**
     * @param array<string, mixed> $claims
     */
    protected function issueForPurpose(SecurityTokenPurpose $purpose, array $claims): string
    {
        $purposeValue = $purpose->value;

        return $this->codec->issue(
            ['purpose' => $purposeValue] + $claims,
            $this->clock->now()->getTimestamp() + $this->ttlSeconds,
            $purposeValue,
        );
    }

    protected function issueSubjectAndClaim(SecurityTokenPurpose $purpose, string $subject, string $claimName, string $claimValue): string
    {
        return $this->issueForPurpose($purpose, [
            'sub' => $subject,
            $claimName => $claimValue,
        ]);
    }

    protected function isValidIdentifier(string $value, string $label): bool
    {
        try {
            $this->assertIdentifier($value, $label);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * @param array<string, string> $expectedStringClaims
     */
    protected function verifyForPurpose(
        SecurityTokenPurpose $purpose,
        #[\SensitiveParameter]
        string $token,
        array $expectedStringClaims = [],
    ): bool {
        try {
            $purposeValue = $purpose->value;
            $claims = $this->codec->verify($token, $purposeValue);

            if (($claims['purpose'] ?? null) !== $purposeValue) {
                return false;
            }

            return array_all($expectedStringClaims, fn($expected, $claimName) => !(!isset($claims[$claimName]) || !is_string($claims[$claimName]) || !hash_equals($claims[$claimName], $expected)));
        } catch (TokenException) {
            return false;
        }
    }

    protected function verifySubjectAndClaim(
        SecurityTokenPurpose $purpose,
        #[\SensitiveParameter]
        string $token,
        string $subject,
        string $claimName,
        string $claimValue,
    ): bool {
        return $this->verifyForPurpose($purpose, $token, [
            'sub' => $subject,
            $claimName => $claimValue,
        ]);
    }
}
