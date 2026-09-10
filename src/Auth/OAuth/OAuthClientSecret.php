<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Password\PasswordHasher;

final readonly class OAuthClientSecret
{
    private const int MAX_HASH_BYTES = 512;

    private const int MAX_SECRET_BYTES = 1_024;

    private function __construct(#[\SensitiveParameter] private string $hash)
    {
        if (strlen($this->hash) > self::MAX_HASH_BYTES) {
            throw new ConfigurationException('OAuth client-secret hash is too large.');
        }

        $algorithm = password_get_info($this->hash)['algoName'];
        if (!in_array($algorithm, ['argon2id', 'bcrypt'], true)) {
            throw new ConfigurationException('OAuth client-secret hash must use an approved password-hash algorithm.');
        }
    }

    public static function fromHash(#[\SensitiveParameter] string $hash): self
    {
        return new self($hash);
    }

    public static function hash(
        #[\SensitiveParameter]
        string $secret,
        ?PasswordHasher $hasher = null,
    ): self {
        self::assertPlaintext($secret);
        $hasher ??= new PasswordHasher();

        return new self($hasher->hashPassword($secret));
    }

    public function encodedHash(): string
    {
        return $this->hash;
    }

    public function verify(#[\SensitiveParameter] string $secret): bool
    {
        if (!self::validPlaintext($secret)) {
            return false;
        }

        return password_verify($secret, $this->hash);
    }

    private static function assertPlaintext(#[\SensitiveParameter] string $secret): void
    {
        if (!self::validPlaintext($secret)) {
            throw new ConfigurationException(sprintf(
                'OAuth client secret must contain between 1 and %d bytes.',
                self::MAX_SECRET_BYTES,
            ));
        }
    }

    private static function validPlaintext(#[\SensitiveParameter] string $secret): bool
    {
        return $secret !== '' && strlen($secret) <= self::MAX_SECRET_BYTES;
    }
}
