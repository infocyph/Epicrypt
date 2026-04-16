<?php

namespace Infocyph\Epicrypt\Token\Contract;

interface OpaqueTokenInterface
{
    public function hash(string $token): string;

    public function issue(int $length = 48): string;

    public function verify(string $token, string $digest): bool;
}
