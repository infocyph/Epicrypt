<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

final readonly class StringUnprotectResult
{
    public function __construct(
        public string $plaintext,
        public ?string $matchedKeyId = null,
        public bool $usedFallbackKey = false,
    ) {}
}
