<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Enum;

enum StreamAlgorithm: string
{
    case UNAUTHENTICATED_XCHACHA20 = 'unauthenticated-xchacha20';

    case XCHACHA20POLY1305 = 'xchacha20poly1305';

    public function keyLength(): int
    {
        return match ($this) {
            self::UNAUTHENTICATED_XCHACHA20 => SODIUM_CRYPTO_STREAM_XCHACHA20_KEYBYTES,
            self::XCHACHA20POLY1305 => SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
        };
    }

    /**
     * @return int<1, max>
     */
    public function prefixLength(): int
    {
        return match ($this) {
            self::UNAUTHENTICATED_XCHACHA20 => SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES,
            self::XCHACHA20POLY1305 => SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
        };
    }

    public function usesSecretStream(): bool
    {
        return $this === self::XCHACHA20POLY1305;
    }
}
