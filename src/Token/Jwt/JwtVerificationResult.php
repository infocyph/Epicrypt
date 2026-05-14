<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

final readonly class JwtVerificationResult
{
    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    public function __construct(
        public bool $verified,
        public array $claims = [],
        public array $headers = [],
        public ?string $matchedKeyId = null,
        public bool $usedFallbackKey = false,
        public bool $expired = false,
        public bool $notBeforeViolation = false,
        public ?string $algorithm = null,
    ) {}
}
