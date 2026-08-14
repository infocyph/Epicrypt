<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Contract\KeyPairGeneratorInterface;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;

final readonly class KeyPairGenerator implements KeyPairGeneratorInterface
{
    public function __construct(
        private ?OpenSslRsaBits $bits = OpenSslRsaBits::BITS_3072,
        private ?OpenSslCurveName $curve = null,
    ) {
        if (($this->bits === null) === ($this->curve === null)) {
            throw new ConfigurationException('Select exactly one OpenSSL RSA size or EC curve.');
        }
    }

    /** @return array{private: string, public: string} */
    public function generate(#[\SensitiveParameter] ?string $passphrase = null, bool $asBase64Url = false): array
    {
        $config = $this->bits !== null
            ? ['private_key_bits' => $this->bits->value, 'private_key_type' => OPENSSL_KEYTYPE_RSA]
            : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $this->curve?->value];

        $resource = openssl_pkey_new($config);
        if ($resource === false) {
            throw new ConfigurationException('OpenSSL key pair generation failed.');
        }

        $privateKey = null;
        if (!openssl_pkey_export($resource, $privateKey, $passphrase, $config)
            || !is_string($privateKey)
            || $privateKey === '') {
            throw new ConfigurationException('Private key export failed.');
        }

        $details = openssl_pkey_get_details($resource);
        if (!is_array($details) || !is_string($details['key'] ?? null) || $details['key'] === '') {
            throw new ConfigurationException('Public key export failed.');
        }

        if (!$asBase64Url) {
            return ['private' => $privateKey, 'public' => $details['key']];
        }

        return [
            'private' => Base64Url::encode($privateKey),
            'public' => Base64Url::encode($details['key']),
        ];
    }
}
