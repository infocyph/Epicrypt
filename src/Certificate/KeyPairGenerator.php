<?php

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Contract\KeyPairGeneratorInterface;
use Infocyph\Epicrypt\Certificate\Enum\KeyPairType;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class KeyPairGenerator implements KeyPairGeneratorInterface
{
    public function __construct(
        private KeyPairGeneratorInterface $backend,
        private KeyPairType $type,
    ) {}

    public static function forType(
        KeyPairType $type,
        OpenSslRsaBits $bits = OpenSslRsaBits::BITS_2048,
        ?OpenSslCurveName $curveName = null,
    ): self {
        if (! $type->isOpenSsl()) {
            return match ($type) {
                KeyPairType::SODIUM_BOX => self::sodium(),
                KeyPairType::SODIUM_SIGN => self::sodiumSign(),
                default => throw new ConfigurationException('Unsupported key pair type.'),
            };
        }

        return self::openSsl($bits, $type->openSslType(), $curveName);
    }

    public static function openSsl(
        OpenSslRsaBits $bits = OpenSslRsaBits::BITS_2048,
        OpenSslKeyType $type = OpenSslKeyType::RSA,
        ?OpenSslCurveName $curveName = null,
    ): self {
        if ($type === OpenSslKeyType::RSA && $curveName !== null) {
            throw new ConfigurationException('OpenSSL RSA key pair generation does not accept a curve selector.');
        }

        $resolvedCurve = $curveName;
        if ($type === OpenSslKeyType::EC && $resolvedCurve === null) {
            $resolvedCurve = OpenSslCurveName::recommended();
        }

        return new self(new OpenSSL\KeyPairGenerator($bits, $type, $resolvedCurve), $type->keyPairType());
    }

    public static function sodium(): self
    {
        return new self(new Sodium\KeyPairGenerator(), KeyPairType::SODIUM_BOX);
    }

    public static function sodiumSign(): self
    {
        return new self(new Sodium\SigningKeyPairGenerator(), KeyPairType::SODIUM_SIGN);
    }

    /**
     * @return array{private: string, public: string}
     */
    public function generate(?string $passphrase = null, bool $asBase64Url = false): array
    {
        return $this->backend->generate($passphrase, $asBase64Url);
    }

    public function type(): KeyPairType
    {
        return $this->type;
    }
}
