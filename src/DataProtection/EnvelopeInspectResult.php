<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

final readonly class EnvelopeInspectResult
{
    public function __construct(
        public int $version,
        public string $algorithm,
        public ?string $keyId,
        public ?string $dekAlgorithm,
        public ?int $createdAt,
        public ?string $purpose,
    ) {}
}
