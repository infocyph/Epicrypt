<?php

namespace Infocyph\Epicrypt\Password\Secret;

use Infocyph\Epicrypt\Internal\Base64Url;

final class MasterSecretGenerator
{
    public function generate(int $length = 32, bool $asBase64Url = true): string
    {
        $secret = random_bytes($length);

        return $asBase64Url ? Base64Url::encode($secret) : $secret;
    }
}
