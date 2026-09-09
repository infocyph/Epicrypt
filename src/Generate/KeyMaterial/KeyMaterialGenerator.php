<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial;

use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyMaterialEncoding;
use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyPurpose;
use Infocyph\Epicrypt\Generate\Support\LengthGuard;
use Infocyph\Epicrypt\Internal\Base64Url;

final class KeyMaterialGenerator
{
    private const int APPLICATION_SECRET_BYTES = 32;

    public function forAead(
        AeadAlgorithm $algorithm = AeadAlgorithm::XCHACHA20_POLY1305_IETF,
        KeyMaterialEncoding $encoding = KeyMaterialEncoding::BASE64URL,
    ): string {
        return $this->generate($algorithm->keyLength(), $encoding);
    }

    public function forMasterSecret(KeyMaterialEncoding $encoding = KeyMaterialEncoding::BASE64URL): string
    {
        return $this->generate(self::APPLICATION_SECRET_BYTES, $encoding);
    }

    public function forPurpose(
        KeyPurpose $purpose,
        KeyMaterialEncoding $encoding = KeyMaterialEncoding::BASE64URL,
    ): string {
        $length = match ($purpose) {
            KeyPurpose::AEAD,
            KeyPurpose::SECRETBOX,
            KeyPurpose::MASTER_SECRET,
            KeyPurpose::WRAPPED_SECRET_MASTER,
            KeyPurpose::SECRETSTREAM,
            KeyPurpose::MAC,
            KeyPurpose::TOKEN_SIGNING,
            KeyPurpose::SIGNED_PAYLOAD => self::APPLICATION_SECRET_BYTES,
        };

        return $this->generate($length, $encoding);
    }

    public function forSecretBox(KeyMaterialEncoding $encoding = KeyMaterialEncoding::BASE64URL): string
    {
        return $this->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $encoding);
    }

    public function forSecretStream(KeyMaterialEncoding $encoding = KeyMaterialEncoding::BASE64URL): string
    {
        return $this->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES, $encoding);
    }

    public function forTokenSecret(KeyMaterialEncoding $encoding = KeyMaterialEncoding::BASE64URL): string
    {
        return $this->generate(self::APPLICATION_SECRET_BYTES, $encoding);
    }

    public function generate(
        int $length = self::APPLICATION_SECRET_BYTES,
        KeyMaterialEncoding $encoding = KeyMaterialEncoding::BASE64URL,
    ): string {
        $material = random_bytes(LengthGuard::atLeastOne($length, 'Key material length'));

        return match ($encoding) {
            KeyMaterialEncoding::RAW => $material,
            KeyMaterialEncoding::BASE64URL => Base64Url::encode($material),
            KeyMaterialEncoding::HEX => bin2hex($material),
        };
    }
}
