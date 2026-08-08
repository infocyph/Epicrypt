<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Psr\Clock\ClockInterface;
use Throwable;

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
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): string {
        return $this->protectResult($plaintext, $key, $options)->value;
    }

    public function protectResult(
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): ProtectionResult {
        return $this->protectWithBinaryKeyResult($plaintext, Base64Url::decode($key), $options);
    }

    public function protectWithBinaryKey(
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): string {
        return $this->protectWithBinaryKeyResult($plaintext, $key, $options)->value;
    }

    public function protectWithBinaryKeyResult(
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
        string $plaintext,
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
        string $payload,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): string {
        return $this->unprotectResult($payload, $key, $options)->value;
    }

    public function unprotectResult(
        string $payload,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): ProtectionResult {
        return $this->unprotectWithBinaryKeyResult($payload, Base64Url::decode($key), $options);
    }

    public function unprotectWithBinaryKey(
        string $payload,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): string {
        return $this->unprotectWithBinaryKeyResult($payload, $key, $options)->value;
    }

    public function unprotectWithBinaryKeyResult(
        string $payload,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
    ): ProtectionResult {
        return ProtectedPayload::decrypt($payload, $key, self::DOMAIN, $options, $this->algorithm);
    }

    public function unprotectWithKeyRing(
        string $payload,
        KeyRing $keyRing,
        ProtectionOptions $options,
    ): ProtectionResult {
        $keyId = ProtectedPayload::keyId($payload, self::DOMAIN, $options, $this->algorithm);
        if ($keyId !== null) {
            $entry = $keyRing->resolveForRead(
                $keyId,
                KeyPurpose::DATA_PROTECTION,
                $this->algorithm->value,
            );
            if ($entry === null) {
                throw new DecryptionException('Protected payload key id is not eligible for decryption.');
            }

            return $this->unprotectResult($payload, $entry->key, $options);
        }

        $lastException = null;
        foreach ($keyRing->readCandidates(KeyPurpose::DATA_PROTECTION, $this->algorithm->value) as $entry) {
            try {
                $result = $this->unprotectResult($payload, $entry->key, $options);

                return new ProtectionResult(
                    $result->value,
                    $result->domain,
                    $result->purpose,
                    $result->createdAt,
                    $entry->id,
                    $entry->status !== \Infocyph\Epicrypt\Security\KeyStatus::ACTIVE,
                );
            } catch (Throwable $exception) {
                $lastException = $exception;
            }
        }

        throw new DecryptionException('Unable to decrypt with an eligible key.', 0, $lastException);
    }
}
