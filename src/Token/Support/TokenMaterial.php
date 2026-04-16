<?php

namespace Infocyph\Epicrypt\Token\Support;

use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;

/**
 * @internal
 */
final readonly class TokenMaterial
{
    public function __construct(
        private TokenMaterialGenerator $generator = new TokenMaterialGenerator(),
    ) {}

    public function generate(int $length = 48): string
    {
        return $this->generator->generate($length);
    }
}
