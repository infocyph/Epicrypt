<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Enum;

enum AeadAlgorithm: string
{
    case AES_256_GCM = 'aes-256-gcm';

    case CHACHA20_POLY1305 = 'chacha20-poly1305';

    case CHACHA20_POLY1305_IETF = 'chacha20-poly1305-ietf';

    case XCHACHA20_POLY1305_IETF = 'xchacha20-poly1305-ietf';

    public function isAvailable(): bool
    {
        return !$this->requiresHardwareSupport() || sodium_crypto_aead_aes256gcm_is_available();
    }

    /**
     * @return int<1, max>
     */
    public function keyLength(): int
    {
        return $this->lengths()['key'];
    }

    /**
     * @return int<1, max>
     */
    public function nonceLength(): int
    {
        return $this->lengths()['nonce'];
    }

    public function requiresHardwareSupport(): bool
    {
        return $this === self::AES_256_GCM;
    }

    public function sodiumSuffix(): string
    {
        return match ($this) {
            self::AES_256_GCM => 'aes256gcm',
            self::CHACHA20_POLY1305 => 'chacha20poly1305',
            self::CHACHA20_POLY1305_IETF => 'chacha20poly1305_ietf',
            self::XCHACHA20_POLY1305_IETF => 'xchacha20poly1305_ietf',
        };
    }

    /**
     * @return array{key: int<1, max>, nonce: int<1, max>}
     */
    private function lengths(): array
    {
        return match ($this) {
            self::AES_256_GCM => ['key' => SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES, 'nonce' => SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES],
            self::CHACHA20_POLY1305 => ['key' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES, 'nonce' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES],
            self::CHACHA20_POLY1305_IETF => ['key' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES, 'nonce' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES],
            self::XCHACHA20_POLY1305_IETF => ['key' => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 'nonce' => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES],
        };
    }
}
