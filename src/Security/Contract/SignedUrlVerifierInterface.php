<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security\Contract;

interface SignedUrlVerifierInterface
{
    public function verify(string $signedUrl): bool;
}
