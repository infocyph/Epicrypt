<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security\Contract;

use Infocyph\Epicrypt\Security\SignedUrlOptions;

interface SignedUrlGeneratorInterface
{
    /**
     * @param array<string, scalar|null> $parameters
     */
    public function generate(string $url, array $parameters = [], ?int $expiresAt = null, ?SignedUrlOptions $options = null): string;
}
