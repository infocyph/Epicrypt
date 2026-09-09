<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Token\Jwt\JwtFailureReason;

final readonly class OAuthAccessTokenValidationResult
{
    /** @param array<string, mixed> $claims */
    private function __construct(
        public OAuthAccessTokenValidationStatus $status,
        public array $claims,
        public ?JwtFailureReason $jwtFailureReason,
        public ?string $matchedKeyId,
    ) {}

    /** @param array<string, mixed> $claims */
    public static function inactive(
        OAuthAccessTokenValidationStatus $status,
        array $claims,
        ?string $matchedKeyId,
    ): self {
        return new self($status, $claims, null, $matchedKeyId);
    }

    public static function invalid(?JwtFailureReason $reason = null): self
    {
        return new self(OAuthAccessTokenValidationStatus::INVALID_TOKEN, [], $reason, null);
    }

    /** @param array<string, mixed> $claims */
    public static function success(array $claims, ?string $matchedKeyId): self
    {
        return new self(OAuthAccessTokenValidationStatus::VALID, $claims, null, $matchedKeyId);
    }

    public function cryptographicallyValid(): bool
    {
        return $this->status !== OAuthAccessTokenValidationStatus::INVALID_TOKEN;
    }

    public function valid(): bool
    {
        return $this->status === OAuthAccessTokenValidationStatus::VALID;
    }
}
