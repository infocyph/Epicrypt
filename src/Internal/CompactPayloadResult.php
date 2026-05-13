<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

/**
 * @internal
 */
final readonly class CompactPayloadResult
{
    public function __construct(
        public bool $versioned,
        public string $algorithm,
        public ?string $keyId,
        public string $nonce,
        public string $ciphertext,
    ) {}
}
