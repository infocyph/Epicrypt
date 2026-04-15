<?php

namespace Infocyph\Epicrypt\Contract;

interface TokenVerifierInterface
{
    public function verify(string $token, mixed $key): bool;
}
