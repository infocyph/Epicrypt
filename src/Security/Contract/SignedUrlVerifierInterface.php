<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security\Contract;

use Infocyph\Epicrypt\Security\SignedUrlOptions;

interface SignedUrlVerifierInterface
{
    public function verify(string $signedUrl, ?SignedUrlOptions $options = null): bool;
}
