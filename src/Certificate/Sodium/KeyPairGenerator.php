<?php

namespace Infocyph\Epicrypt\Certificate\Sodium;

use Infocyph\Epicrypt\Certificate\Contract\KeyPairGeneratorInterface;
use Infocyph\Epicrypt\Internal\Base64Url;

final class KeyPairGenerator implements KeyPairGeneratorInterface
{
    /**
     * @return array{private: string, public: string}
     */
    public function generate(?string $passphrase = null, bool $asBase64Url = false): array
    {
        $keypair = sodium_crypto_box_keypair();
        $private = sodium_crypto_box_secretkey($keypair);
        $public = sodium_crypto_box_publickey($keypair);

        if (! $asBase64Url) {
            return ['private' => $private, 'public' => $public];
        }

        return ['private' => Base64Url::encode($private), 'public' => Base64Url::encode($public)];
    }
}
