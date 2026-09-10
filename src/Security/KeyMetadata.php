<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

final readonly class KeyMetadata
{
    public function __construct(
        public string $id,
        public KeyStatus $status,
        public KeyPurpose $purpose,
        public string $algorithm,
        public ?int $notBefore = null,
        public ?int $notAfter = null,
        public ?string $issuer = null,
    ) {}
}
