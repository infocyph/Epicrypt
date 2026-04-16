<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Contract\KeyPairGeneratorInterface;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;

final readonly class KeyPairGenerator implements KeyPairGeneratorInterface
{
    public function __construct(
        private OpenSslRsaBits $bits = OpenSslRsaBits::BITS_2048,
        private OpenSslKeyType $type = OpenSslKeyType::RSA,
        private ?OpenSslCurveName $curveName = null,
    ) {}

    /**
     * @return array{private: string, public: string}
     */
    public function generate(?string $passphrase = null, bool $asBase64Url = false): array
    {
        $config = [
            'private_key_bits' => $this->bits->value,
            'private_key_type' => $this->type->value,
        ];

        if ($this->curveName !== null) {
            $config['curve_name'] = $this->curveName->value;
        }

        $resource = openssl_pkey_new($config);
        if ($resource === false) {
            throw new ConfigurationException('OpenSSL key pair generation failed.');
        }

        $privateKey = null;
        $exported = openssl_pkey_export($resource, $privateKey, $passphrase ?? '');
        if (!$exported || !is_string($privateKey) || $privateKey === '') {
            throw new ConfigurationException('Failed to export private key.');
        }

        $details = openssl_pkey_get_details($resource);
        if (!is_array($details) || !isset($details['key']) || !is_string($details['key']) || $details['key'] === '') {
            throw new ConfigurationException('Failed to export public key.');
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
