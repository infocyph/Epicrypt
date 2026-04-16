<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate;

use Infocyph\Epicrypt\Generate\Support\LengthGuard;
use Infocyph\Epicrypt\Internal\Base64Url;

final class NonceGenerator
{
    public function generate(int $length = 24, bool $asBase64Url = true): string
    {
        $nonce = random_bytes(LengthGuard::atLeastOne($length, 'Nonce length'));

        return $asBase64Url ? Base64Url::encode($nonce) : $nonce;
    }
}
