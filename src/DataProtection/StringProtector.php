<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyStatus;
use Psr\Clock\ClockInterface;

final readonly class StringProtector
{
    private const string DOMAIN = 'string';

    public function __construct(
        private ClockInterface $clock = new SystemClock(),
        private ProtectionAlgorithm $algorithm = ProtectionAlgorithm::XCHACHA20_POLY1305,
    ) {
        if (!$this->algorithm->isAvailable()) {
            throw new ConfigurationException(sprintf(
                'Protection algorithm "%s" is not available on this platform.',
                $this->algorithm->value,
            ));
        }
    }

    public static function create(
        ProtectionAlgorithm $algorithm = ProtectionAlgorithm::XCHACHA20_POLY1305,
    ): self {
        return new self(algorithm: $algorithm);
    }

    public function protect(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): string {
        return $this->protectResult($plaintext, $key, $options)->value;
    }

    public function protectResult(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): ProtectionResult {
        return $this->protectWithBinaryKeyResult($plaintext, Base64Url::decode($key), $options);
    }

    public function protectWithBinaryKey(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): string {
        return $this->protectWithBinaryKeyResult($plaintext, $key, $options)->value;
    }

    public function protectWithBinaryKeyResult(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): ProtectionResult {
        return ProtectedPayload::encrypt(
            $plaintext,
            $key,
            self::DOMAIN,
            $options,
            $this->clock->now()->getTimestamp(),
            $this->algorithm,
        );
    }

    public function protectWithKeyRing(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        KeyRing $keyRing,
        ProtectionOptions $options,
    ): string {
        $entry = $keyRing->activeForWrite(KeyPurpose::DATA_PROTECTION, $this->algorithm->value);

        return $this->protect(
            $plaintext,
            $entry->key,
            new ProtectionOptions(
                $options->purpose,
                $options->additionalAuthenticatedData,
                $entry->id,
            ),
        );
    }

    public function unprotect(
        #[\SensitiveParameter]
        string $payload,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): string {
        return $this->unprotectResult($payload, $key, $options)->value;
    }

    public function unprotectResult(
        #[\SensitiveParameter]
        string $payload,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): ProtectionResult {
        return $this->unprotectWithBinaryKeyResult($payload, Base64Url::decode($key), $options);
    }

    public function unprotectWithBinaryKey(
        #[\SensitiveParameter]
        string $payload,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): string {
        return $this->unprotectWithBinaryKeyResult($payload, $key, $options)->value;
    }

    public function unprotectWithBinaryKeyResult(
        #[\SensitiveParameter]
        string $payload,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): ProtectionResult {
        return ProtectedPayload::decrypt($payload, $key, self::DOMAIN, $options, $this->algorithm);
    }

    public function unprotectWithKeyRing(
        #[\SensitiveParameter]
        string $payload,
        #[\SensitiveParameter]
        KeyRing $keyRing,
        ProtectionOptions $options,
    ): ProtectionResult {
        $keyId = ProtectedPayload::keyId($payload, self::DOMAIN, $options, $this->algorithm);
        if ($keyId === null) {
            throw new DecryptionException('Protected payload key id is required for KeyRing decryption.');
        }

        $entry = $keyRing->resolveForRead(
            $keyId,
            KeyPurpose::DATA_PROTECTION,
            $this->algorithm->value,
        );
        if ($entry === null) {
            throw new DecryptionException('Protected payload key id is not eligible for decryption.');
        }
        $result = $this->unprotectResult($payload, $entry->key, $options);

        return new ProtectionResult(
            $result->value,
            $result->domain,
            $result->purpose,
            $result->createdAt,
            $entry->id,
            $entry->status === KeyStatus::FALLBACK,
        );
    }
}
