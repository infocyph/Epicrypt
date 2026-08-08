<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

final readonly class JwtVerificationResult
{
    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    private function __construct(
        public bool $valid,
        public array $claims,
        public array $headers,
        public ?JwtFailureReason $failureReason,
        public ?string $matchedKeyId,
    ) {}

    public static function failure(JwtFailureReason $reason): self
    {
        return new self(false, [], [], $reason, null);
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    public static function success(array $claims, array $headers, ?string $matchedKeyId = null): self
    {
        return new self(true, $claims, $headers, null, $matchedKeyId);
    }
}
