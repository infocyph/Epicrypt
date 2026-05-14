<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Sodium;

use Infocyph\Epicrypt\Certificate\Contract\KeyPairGeneratorInterface;
use Infocyph\Epicrypt\Certificate\Sodium\Support\SodiumKeyPairFactory;

final class KeyPairGenerator implements KeyPairGeneratorInterface
{
    /**
     * @return array{private: string, public: string}
     */
    public function generate(?string $passphrase = null, bool $asBase64Url = false): array
    {
        unset($passphrase);

        return SodiumKeyPairFactory::generate(
            createKeyPair: sodium_crypto_box_keypair(...),
            extractPrivate: sodium_crypto_box_secretkey(...),
            extractPublic: sodium_crypto_box_publickey(...),
            asBase64Url: $asBase64Url,
        );
    }
}
