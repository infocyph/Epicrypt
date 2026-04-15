<?php

namespace Infocyph\Epicrypt\Generate\KeyMaterial;

use Infocyph\Epicrypt\Internal\Base64Url;

final class KeyMaterialGenerator
{
    public function generate(int $length = 32, bool $asBase64Url = true): string
    {
        $material = random_bytes($length);

        return $asBase64Url ? Base64Url::encode($material) : $material;
    }
}
