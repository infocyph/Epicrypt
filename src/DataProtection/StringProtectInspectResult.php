<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

final readonly class StringProtectInspectResult
{
    public function __construct(
        public string $version,
        public string $algorithm,
        public ?string $keyId,
    ) {}
}
