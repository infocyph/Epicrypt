<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial;

use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyPurpose;
use Infocyph\Epicrypt\Generate\Support\LengthGuard;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

final class KeyMaterialGenerator
{
    public function forAead(AeadAlgorithm $algorithm = AeadAlgorithm::XCHACHA20_POLY1305_IETF, bool $asBase64Url = true): string
    {
        return $this->generate($algorithm->keyLength(), $asBase64Url);
    }

    public function forMasterSecret(bool $asBase64Url = true): string
    {
        return $this->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $asBase64Url);
    }

    public function forPurpose(KeyPurpose $purpose, SecurityProfile $profile = SecurityProfile::MODERN, bool $asBase64Url = true): string
    {
        return $this->generate($profile->recommendedKeyLength($purpose), $asBase64Url);
    }

    public function forSecretBox(bool $asBase64Url = true): string
    {
        return $this->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $asBase64Url);
    }

    public function forSecretStream(bool $asBase64Url = true): string
    {
        return $this->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES, $asBase64Url);
    }

    public function generate(int $length = 32, bool $asBase64Url = true): string
    {
        $material = random_bytes(LengthGuard::atLeastOne($length, 'Key material length'));

        return $asBase64Url ? Base64Url::encode($material) : $material;
    }
}
