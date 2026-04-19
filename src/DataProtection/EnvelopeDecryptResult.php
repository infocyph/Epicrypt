<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

final readonly class EnvelopeDecryptResult
{
    public function __construct(
        public string $plaintext,
        public ?string $matchedKeyId = null,
        public bool $usedFallbackKey = false,
    ) {}
}
