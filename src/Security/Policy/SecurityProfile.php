<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security\Policy;

use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyPurpose;
use Infocyph\Epicrypt\Internal\SecurityPolicy as InternalSecurityPolicy;
use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;

enum SecurityProfile: string
{
    case COMPATIBILITY = 'compatibility';

    case LEGACY_DECRYPT_ONLY = 'legacy-decrypt-only';

    case MODERN = 'modern';

    public function allowsLegacyDecrypt(): bool
    {
        return $this !== self::MODERN;
    }

    public function defaultAeadAlgorithm(): AeadAlgorithm
    {
        return match ($this) {
            self::MODERN, self::COMPATIBILITY, self::LEGACY_DECRYPT_ONLY => AeadAlgorithm::XCHACHA20_POLY1305_IETF,
        };
    }

    public function defaultAsymmetricJwtAlgorithm(): AsymmetricJwtAlgorithm
    {
        return match ($this) {
            self::MODERN, self::COMPATIBILITY, self::LEGACY_DECRYPT_ONLY => AsymmetricJwtAlgorithm::RS512,
        };
    }

    public function defaultPasswordAlgorithm(): PasswordHashAlgorithm
    {
        return match ($this) {
            self::MODERN, self::COMPATIBILITY, self::LEGACY_DECRYPT_ONLY => PasswordHashAlgorithm::ARGON2ID,
        };
    }

    public function defaultStreamAlgorithm(): StreamAlgorithm
    {
        return match ($this) {
            self::MODERN, self::COMPATIBILITY, self::LEGACY_DECRYPT_ONLY => StreamAlgorithm::XCHACHA20POLY1305,
        };
    }

    public function defaultSymmetricJwtAlgorithm(): SymmetricJwtAlgorithm
    {
        return match ($this) {
            self::MODERN, self::COMPATIBILITY, self::LEGACY_DECRYPT_ONLY => SymmetricJwtAlgorithm::HS512,
        };
    }

    public function passwordDerivationMemLimit(): int
    {
        return match ($this) {
            self::MODERN => SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            self::COMPATIBILITY => SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            self::LEGACY_DECRYPT_ONLY => SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        };
    }

    public function passwordDerivationOpsLimit(): int
    {
        return match ($this) {
            self::MODERN => SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            self::COMPATIBILITY => SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            self::LEGACY_DECRYPT_ONLY => SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        };
    }

    /**
     * @return array<string, mixed>
     */
    public function passwordHashOptions(): array
    {
        return match ($this) {
            self::MODERN => [
                'algorithm' => $this->defaultPasswordAlgorithm(),
                'memory_cost' => InternalSecurityPolicy::PASSWORD_DEFAULT_MEMORY_COST,
                'time_cost' => InternalSecurityPolicy::PASSWORD_DEFAULT_TIME_COST,
                'threads' => InternalSecurityPolicy::PASSWORD_DEFAULT_THREADS,
            ],
            self::COMPATIBILITY => [
                'algorithm' => $this->defaultPasswordAlgorithm(),
                'memory_cost' => InternalSecurityPolicy::PASSWORD_DEFAULT_MEMORY_COST,
                'time_cost' => InternalSecurityPolicy::PASSWORD_DEFAULT_TIME_COST,
                'threads' => max(1, min(InternalSecurityPolicy::PASSWORD_DEFAULT_THREADS, 2)),
            ],
            self::LEGACY_DECRYPT_ONLY => [
                'algorithm' => $this->defaultPasswordAlgorithm(),
                'memory_cost' => InternalSecurityPolicy::PASSWORD_DEFAULT_MEMORY_COST,
                'time_cost' => InternalSecurityPolicy::PASSWORD_DEFAULT_TIME_COST,
                'threads' => InternalSecurityPolicy::PASSWORD_DEFAULT_THREADS,
            ],
        };
    }

    public function recommendedKeyLength(KeyPurpose $purpose): int
    {
        return match ($purpose) {
            KeyPurpose::AEAD => $this->defaultAeadAlgorithm()->keyLength(),
            KeyPurpose::SECRETBOX, KeyPurpose::MASTER_SECRET, KeyPurpose::WRAPPED_SECRET_MASTER => SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            KeyPurpose::SECRETSTREAM => SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
            KeyPurpose::MAC, KeyPurpose::TOKEN_SIGNING, KeyPurpose::SIGNED_PAYLOAD => 32,
        };
    }
}
