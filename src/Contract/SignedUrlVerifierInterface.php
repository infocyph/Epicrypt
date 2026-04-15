<?php

namespace Infocyph\Epicrypt\Contract;

interface SignedUrlVerifierInterface
{
    public function verify(string $signedUrl): bool;
}
