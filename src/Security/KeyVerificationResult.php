<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

final readonly class KeyVerificationResult
{
    public function __construct(
        public bool $verified,
        public ?string $matchedKeyId = null,
        public bool $usedFallbackKey = false,
    ) {}
}
