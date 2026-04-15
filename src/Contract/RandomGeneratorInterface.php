<?php

namespace Infocyph\Epicrypt\Contract;

interface RandomGeneratorInterface
{
    public function bytes(int $length): string;

    public function string(int $length, string $prefix = '', string $postfix = ''): string;
}
