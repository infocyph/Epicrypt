<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security\Support;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;

abstract readonly class AbstractPurposeToken
{
    private SignedPayloadCodec $codec;

    public function __construct(
        string $secret,
        protected int $ttlSeconds,
    ) {
        $this->codec = new SignedPayloadCodec($secret);
    }

    /**
     * @param array<string, mixed> $claims
     */
    protected function issueForPurpose(SecurityTokenPurpose $purpose, array $claims): string
    {
        $purposeValue = $purpose->value;

        return $this->codec->issue(
            ['purpose' => $purposeValue] + $claims,
            time() + $this->ttlSeconds,
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

    /**
     * @param array<string, string|null> $expectedStringClaims
     */
    protected function verifyForPurpose(SecurityTokenPurpose $purpose, string $token, array $expectedStringClaims = []): bool
    {
        try {
            $purposeValue = $purpose->value;
            $claims = $this->codec->verify($token, $purposeValue);

            if (($claims['purpose'] ?? null) !== $purposeValue) {
                return false;
            }

            foreach ($expectedStringClaims as $claimName => $expected) {
                if ($expected === null) {
                    continue;
                }

                if (!isset($claims[$claimName]) || !is_string($claims[$claimName]) || !hash_equals($claims[$claimName], $expected)) {
                    return false;
                }
            }

            return true;
        } catch (TokenException) {
            return false;
        }
    }

    protected function verifySubjectAndClaim(
        SecurityTokenPurpose $purpose,
        string $token,
        ?string $subject,
        string $claimName,
        ?string $claimValue,
    ): bool {
        return $this->verifyForPurpose($purpose, $token, [
            'sub' => $subject,
            $claimName => $claimValue,
        ]);
    }
}
