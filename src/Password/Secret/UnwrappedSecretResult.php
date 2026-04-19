<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Secret;

final readonly class UnwrappedSecretResult
{
    public function __construct(
        public string $plaintext,
        public ?string $matchedKeyId = null,
        public bool $usedFallbackKey = false,
    ) {}
}
