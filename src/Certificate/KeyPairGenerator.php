<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Contract\KeyPairGeneratorInterface;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class KeyPairGenerator implements KeyPairGeneratorInterface
{
    private function __construct(
        private KeyPairGeneratorInterface $backend,
        private bool $supportsPassphrase,
    ) {}

    public static function ec(OpenSslCurveName $curve = OpenSslCurveName::PRIME256V1): self
    {
        return new self(new OpenSSL\KeyPairGenerator(null, $curve), true);
    }

    public static function rsa(OpenSslRsaBits $bits = OpenSslRsaBits::BITS_3072): self
    {
        return new self(new OpenSSL\KeyPairGenerator($bits), true);
    }

    public static function sodium(): self
    {
        return new self(new Sodium\KeyPairGenerator(), false);
    }

    public static function sodiumSign(): self
    {
        return new self(new Sodium\SigningKeyPairGenerator(), false);
    }

    /** @return array{private: string, public: string} */
    public function generate(#[\SensitiveParameter] ?string $passphrase = null, bool $asBase64Url = false): array
    {
        if (!$this->supportsPassphrase && $passphrase !== null) {
            throw new ConfigurationException('Sodium key generation does not support passphrases.');
        }

        return $this->backend->generate($passphrase, $asBase64Url);
    }
}
