<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;

enum ProtectionAlgorithm: string
{
    case AES_256_GCM = 'aes-256-gcm';

    case XCHACHA20_POLY1305 = 'xchacha20-poly1305-ietf';

    public function isAvailable(): bool
    {
        return $this->aeadAlgorithm()->isAvailable();
    }

    /** @return int<1, max> */
    public function keyLength(): int
    {
        return $this->aeadAlgorithm()->keyLength();
    }

    /** @return int<1, max> */
    public function nonceLength(): int
    {
        return $this->aeadAlgorithm()->nonceLength();
    }

    private function aeadAlgorithm(): AeadAlgorithm
    {
        return match ($this) {
            self::AES_256_GCM => AeadAlgorithm::AES_256_GCM,
            self::XCHACHA20_POLY1305 => AeadAlgorithm::XCHACHA20_POLY1305_IETF,
        };
    }
}
