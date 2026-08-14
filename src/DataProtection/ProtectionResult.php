<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

final readonly class ProtectionResult
{
    public function __construct(
        #[\SensitiveParameter]
        public string $value,
        public string $domain,
        public string $purpose,
        public int $createdAt,
        public ?string $keyId = null,
        public bool $usedFallbackKey = false,
    ) {}
}
