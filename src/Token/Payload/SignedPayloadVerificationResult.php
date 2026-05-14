<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Payload;

final readonly class SignedPayloadVerificationResult
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public bool $verified,
        public array $claims = [],
        public ?string $matchedKeyId = null,
        public bool $usedFallbackKey = false,
        public bool $expired = false,
    ) {}
}
