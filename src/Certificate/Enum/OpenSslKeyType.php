<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Enum;

enum OpenSslKeyType: int
{
    case EC = OPENSSL_KEYTYPE_EC;

    case RSA = OPENSSL_KEYTYPE_RSA;

    public static function fromKeyPairType(KeyPairType $type): self
    {
        return $type->openSslType();
    }

    public function keyPairType(): KeyPairType
    {
        return match ($this) {
            self::RSA => KeyPairType::OPENSSL_RSA,
            self::EC => KeyPairType::OPENSSL_EC,
        };
    }
}
