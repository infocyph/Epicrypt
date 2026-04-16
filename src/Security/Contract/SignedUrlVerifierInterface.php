<?php

namespace Infocyph\Epicrypt\Security\Contract;

interface SignedUrlVerifierInterface
{
    public function verify(string $signedUrl): bool;
}
