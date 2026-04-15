<?php

namespace Infocyph\Epicrypt\Crypto\Support;

use Infocyph\Epicrypt\Internal\Base64Url;

final class KeyPair
{
    /**
     * @return array{private: string, public: string}
     */
    public static function sodiumBox(bool $asBase64Url = true): array
    {
        $keypair = sodium_crypto_box_keypair();
        $private = sodium_crypto_box_secretkey($keypair);
        $public = sodium_crypto_box_publickey($keypair);

        if (! $asBase64Url) {
            return ['private' => $private, 'public' => $public];
        }

        return [
            'private' => Base64Url::encode($private),
            'public' => Base64Url::encode($public),
        ];
    }
    /**
     * @return array{private: string, public: string}
     */
    public static function sodiumSign(bool $asBase64Url = true): array
    {
        $keypair = sodium_crypto_sign_keypair();

        $private = sodium_crypto_sign_secretkey($keypair);
        $public = sodium_crypto_sign_publickey($keypair);

        if (! $asBase64Url) {
            return ['private' => $private, 'public' => $public];
        }

        return [
            'private' => Base64Url::encode($private),
            'public' => Base64Url::encode($public),
        ];
    }
}
