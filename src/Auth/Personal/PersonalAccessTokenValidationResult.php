<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

use Infocyph\Epicrypt\Token\Jwt\JwtFailureReason;

final readonly class PersonalAccessTokenValidationResult
{
    private function __construct(
        public PersonalAccessTokenValidationStatus $status,
        public ?PersonalAccessTokenRecord $record = null,
        public ?PersonalAccessTokenAbilities $abilities = null,
        public ?JwtFailureReason $failureReason = null,
        public ?int $lastUsedAt = null,
    ) {}

    public static function inactive(): self
    {
        return new self(PersonalAccessTokenValidationStatus::INACTIVE);
    }

    public static function invalid(?JwtFailureReason $failureReason = null): self
    {
        return new self(PersonalAccessTokenValidationStatus::INVALID, failureReason: $failureReason);
    }

    public static function stateMismatch(): self
    {
        return new self(PersonalAccessTokenValidationStatus::STATE_MISMATCH);
    }

    public static function valid(
        PersonalAccessTokenRecord $record,
        PersonalAccessTokenAbilities $abilities,
        ?int $lastUsedAt = null,
    ): self {
        return new self(PersonalAccessTokenValidationStatus::VALID, $record, $abilities, lastUsedAt: $lastUsedAt);
    }

    public function accepted(): bool
    {
        return $this->status === PersonalAccessTokenValidationStatus::VALID;
    }

    public function allows(string $ability): bool
    {
        return $this->accepted() && $this->abilities?->allows($ability) === true;
    }
}
