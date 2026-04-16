<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Enum;

use Infocyph\Epicrypt\Exception\ConfigurationException;

enum KeyPairType: string
{
    case OPENSSL_EC = 'openssl_ec';

    case OPENSSL_RSA = 'openssl_rsa';

    case SODIUM_BOX = 'sodium_box';

    case SODIUM_SIGN = 'sodium_sign';

    public function isOpenSsl(): bool
    {
        return $this === self::OPENSSL_RSA || $this === self::OPENSSL_EC;
    }

    public function openSslType(): OpenSslKeyType
    {
        return match ($this) {
            self::OPENSSL_RSA => OpenSslKeyType::RSA,
            self::OPENSSL_EC => OpenSslKeyType::EC,
            default => throw new ConfigurationException('Only OpenSSL key pair types can be converted to OpenSSL key type selectors.'),
        };
    }
}
