<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

final readonly class ProtectionMetadata
{
    public function __construct(
        public string $domain,
        public string $purpose,
        public int $createdAt,
        public ?string $keyId = null,
        public bool $usedFallbackKey = false,
    ) {}
}
