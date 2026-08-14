<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Sodium;

use Infocyph\Epicrypt\Certificate\Contract\KeyPairGeneratorInterface;
use Infocyph\Epicrypt\Certificate\Sodium\Support\SodiumKeyPairFactory;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class SigningKeyPairGenerator implements KeyPairGeneratorInterface
{
    /**
     * @return array{private: string, public: string}
     */
    public function generate(#[\SensitiveParameter] ?string $passphrase = null, bool $asBase64Url = false): array
    {
        if ($passphrase !== null) {
            throw new ConfigurationException('Sodium signing-key generation does not support passphrases.');
        }

        return SodiumKeyPairFactory::generate(
            createKeyPair: sodium_crypto_sign_keypair(...),
            extractPrivate: static function (string $keyPair): string {
                if ($keyPair === '') {
                    throw new \RuntimeException('Signing key pair is empty.');
                }

                return sodium_crypto_sign_secretkey($keyPair);
            },
            extractPublic: static function (string $keyPair): string {
                if ($keyPair === '') {
                    throw new \RuntimeException('Signing key pair is empty.');
                }

                return sodium_crypto_sign_publickey($keyPair);
            },
            asBase64Url: $asBase64Url,
        );
    }
}
