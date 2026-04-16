<?php

namespace Infocyph\Epicrypt\Integrity\Support;

use Infocyph\Epicrypt\Integrity\Contract\HasherInterface;

/**
 * @internal
 */
final readonly class DigestVerifier
{
    public function __construct(
        private HasherInterface $hasher,
    ) {}

    /**
     * @param array<string, mixed> $options
     */
    public function verify(string $content, string $digest, array $options = []): bool
    {
        return $this->hasher->verify($content, $digest, $options);
    }
}
