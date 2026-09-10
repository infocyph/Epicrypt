<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class RefreshTokenInspectionResult
{
    private function __construct(
        public RefreshTokenInspectionStatus $status,
        public ?RefreshTokenRecord $record,
    ) {}

    public static function of(RefreshTokenInspectionStatus $status, ?RefreshTokenRecord $record = null): self
    {
        return new self($status, $record);
    }

    public function active(): bool
    {
        return $this->status === RefreshTokenInspectionStatus::ACTIVE;
    }

    public function grant(): ?RefreshTokenGrant
    {
        return $this->record?->grant;
    }
}
