<?php

namespace Infocyph\Epicrypt\Generate\KeyMaterial;

use Infocyph\Epicrypt\Generate\Random\RandomBytesGenerator;

final readonly class TokenMaterialGenerator
{
    public function __construct(
        private RandomBytesGenerator $generator = new RandomBytesGenerator(),
    ) {}

    public function generate(int $length = 48): string
    {
        return $this->generator->string($length);
    }
}
