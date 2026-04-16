<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Enum;

enum StreamAlgorithm: string
{
    case XCHACHA20 = 'xchacha20';

    case XCHACHA20POLY1305 = 'xchacha20poly1305';

    /**
     * @return int<1, max>
     */
    public function prefixLength(): int
    {
        return match ($this) {
            self::XCHACHA20 => SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES,
            self::XCHACHA20POLY1305 => SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES,
        };
    }

    public function usesSecretStream(): bool
    {
        return $this === self::XCHACHA20POLY1305;
    }
}
