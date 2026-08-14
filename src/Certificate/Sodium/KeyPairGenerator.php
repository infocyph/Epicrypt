<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Sodium;

use Infocyph\Epicrypt\Certificate\Contract\KeyPairGeneratorInterface;
use Infocyph\Epicrypt\Certificate\Sodium\Support\SodiumKeyPairFactory;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class KeyPairGenerator implements KeyPairGeneratorInterface
{
    /**
     * @return array{private: string, public: string}
     */
    public function generate(#[\SensitiveParameter] ?string $passphrase = null, bool $asBase64Url = false): array
    {
        if ($passphrase !== null) {
            throw new ConfigurationException('Sodium key generation does not support passphrases.');
        }

        return SodiumKeyPairFactory::generate(
            createKeyPair: sodium_crypto_box_keypair(...),
            extractPrivate: sodium_crypto_box_secretkey(...),
            extractPublic: sodium_crypto_box_publickey(...),
            asBase64Url: $asBase64Url,
        );
    }
}
