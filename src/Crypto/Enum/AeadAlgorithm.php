<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Enum;

enum AeadAlgorithm: string
{
    case AEGIS_128L = 'aegis-128l';

    case AEGIS_256 = 'aegis-256';

    case AES_256_GCM = 'aes-256-gcm';

    case CHACHA20_POLY1305 = 'chacha20-poly1305';

    case CHACHA20_POLY1305_IETF = 'chacha20-poly1305-ietf';

    case XCHACHA20_POLY1305_IETF = 'xchacha20-poly1305-ietf';

    public function isAvailable(): bool
    {
        return match ($this) {
            self::AES_256_GCM => sodium_crypto_aead_aes256gcm_is_available(),
            self::AEGIS_128L => function_exists('sodium_crypto_aead_aegis128l_encrypt'),
            self::AEGIS_256 => function_exists('sodium_crypto_aead_aegis256_encrypt'),
            default => true,
        };
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
            self::AEGIS_128L => 'aegis128l',
            self::AEGIS_256 => 'aegis256',
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
            self::AEGIS_128L => ['key' => 16, 'nonce' => 16],
            self::AEGIS_256 => ['key' => 32, 'nonce' => 32],
            self::CHACHA20_POLY1305 => ['key' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES, 'nonce' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES],
            self::CHACHA20_POLY1305_IETF => ['key' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES, 'nonce' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES],
            self::XCHACHA20_POLY1305_IETF => ['key' => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 'nonce' => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES],
        };
    }
}
