<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Sodium;

final readonly class DirectionalSessionKeys
{
    public function __construct(
        #[\SensitiveParameter]
        public string $receiveKey,
        #[\SensitiveParameter]
        public string $transmitKey,
    ) {}
}
