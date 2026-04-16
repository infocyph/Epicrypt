<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\Contract;

interface RandomGeneratorInterface
{
    public function bytes(int $length): string;

    public function string(int $length, string $prefix = '', string $postfix = ''): string;
}
