<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

final readonly class SignedUrlVerificationResult
{
    public function __construct(
        public bool $verified,
        public bool $expired = false,
        public bool $invalidSignature = false,
        public ?int $expiresAt = null,
        public ?int $version = null,
    ) {}
}
