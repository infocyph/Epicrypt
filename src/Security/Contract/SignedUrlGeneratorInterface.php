<?php

namespace Infocyph\Epicrypt\Security\Contract;

interface SignedUrlGeneratorInterface
{
    /**
     * @param array<string, scalar|null> $parameters
     */
    public function generate(string $url, array $parameters = [], ?int $expiresAt = null): string;
}
