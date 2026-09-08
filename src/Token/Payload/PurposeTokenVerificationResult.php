<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Payload;

final readonly class PurposeTokenVerificationResult
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public bool $verified,
        public ?PurposeTokenFailureReason $failureReason = null,
        #[\SensitiveParameter]
        public array $claims = [],
        public ?string $subjectId = null,
        public ?string $tokenId = null,
        public ?int $issuedAt = null,
        public ?int $notBefore = null,
        public ?int $expiresAt = null,
        public ?string $matchedKeyId = null,
        public bool $usedFallbackKey = false,
    ) {}
}
