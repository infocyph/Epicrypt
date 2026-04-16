<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Secret;

use Infocyph\Epicrypt\Generate\Support\LengthGuard;
use Infocyph\Epicrypt\Internal\Base64Url;

final class MasterSecretGenerator
{
    public function generate(int $length = 32, bool $asBase64Url = true): string
    {
        $secret = random_bytes(LengthGuard::atLeastOne($length, 'Master secret length'));

        return $asBase64Url ? Base64Url::encode($secret) : $secret;
    }
}
