<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

final readonly class FileMigrationResult
{
    public function __construct(
        public string $outputPath,
        public ?string $matchedKeyId = null,
        public bool $usedFallbackKey = false,
    ) {}
}
