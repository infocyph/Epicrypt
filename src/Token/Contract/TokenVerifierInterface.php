<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Contract;

interface TokenVerifierInterface
{
    public function verify(string $token, mixed $key): bool;
}
