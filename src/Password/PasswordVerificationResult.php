<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

final readonly class PasswordVerificationResult
{
    public function __construct(
        public bool $verified,
        public bool $needsRehash,
        public ?string $rehashedHash = null,
    ) {}
}
