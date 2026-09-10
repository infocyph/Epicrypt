<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyStatus;
use Psr\Clock\ClockInterface;

final readonly class EnvelopeProtector
{
    private const string CONTENT_DOMAIN = 'envelope-content';

    private const string DOMAIN = 'envelope';

    private const int MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024;

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
        string $masterKey,
        ProtectionOptions $options,
    ): string {
        return $this->protectResult($plaintext, $masterKey, $options)->value;
    }

    public function protectResult(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $masterKey,
        ProtectionOptions $options,
    ): ProtectionResult {
        return $this->protectWithBinaryKeyResult($plaintext, Base64Url::decode($masterKey), $options);
    }

    public function protectWithBinaryKeyResult(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $masterKey,
        ProtectionOptions $options,
    ): ProtectionResult {
        if (strlen($plaintext) > self::MAX_PLAINTEXT_BYTES) {
            throw new EncryptionException('Envelope plaintext exceeds the 8 MiB protected-value size bound.');
        }

        $createdAt = $this->clock->now()->getTimestamp();
        $dataKey = random_bytes($this->algorithm->keyLength());
        $contentOptions = new ProtectionOptions(
            $options->purpose,
            $options->additionalAuthenticatedData,
        );

        try {
            $content = ProtectedPayload::encrypt(
                $plaintext,
                $dataKey,
                self::CONTENT_DOMAIN,
                $contentOptions,
                $createdAt,
                $this->algorithm,
            );
            $envelope = Json::encode([
                'data_key' => Base64Url::encode($dataKey),
                'protected_content' => $content->value,
            ]);

            return ProtectedPayload::encrypt(
                $envelope,
                $masterKey,
                self::DOMAIN,
                $options,
                $createdAt,
                $this->algorithm,
            );
        } finally {
            sodium_memzero($dataKey);
        }
    }

    public function protectWithKeyRing(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        KeyRing $keyRing,
        ProtectionOptions $options,
    ): string {
        $entry = $keyRing->activeForWrite(KeyPurpose::ENVELOPE_PROTECTION, $this->algorithm->value);

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
        string $masterKey,
        ProtectionOptions $options,
    ): string {
        return $this->unprotectResult($payload, $masterKey, $options)->value;
    }

    public function unprotectResult(
        #[\SensitiveParameter]
        string $payload,
        #[\SensitiveParameter]
        string $masterKey,
        ProtectionOptions $options,
    ): ProtectionResult {
        return $this->unprotectWithBinaryKeyResult($payload, Base64Url::decode($masterKey), $options);
    }

    public function unprotectWithBinaryKeyResult(
        #[\SensitiveParameter]
        string $payload,
        #[\SensitiveParameter]
        string $masterKey,
        ProtectionOptions $options,
    ): ProtectionResult {
        $outer = ProtectedPayload::decrypt($payload, $masterKey, self::DOMAIN, $options, $this->algorithm);
        $envelope = Json::decodeToArray($outer->value);
        $keys = array_keys($envelope);
        sort($keys);
        if ($keys !== ['data_key', 'protected_content']) {
            throw new DecryptionException('Invalid Epicrypt 2.0 envelope fields.');
        }
        $encodedDataKey = $envelope['data_key'] ?? null;
        $protectedContent = $envelope['protected_content'] ?? null;
        if (!is_string($encodedDataKey) || !is_string($protectedContent)) {
            throw new DecryptionException('Invalid Epicrypt 2.0 envelope content.');
        }

        $dataKey = Base64Url::decode($encodedDataKey);

        try {
            $result = ProtectedPayload::decrypt(
                $protectedContent,
                $dataKey,
                self::CONTENT_DOMAIN,
                new ProtectionOptions(
                    $options->purpose,
                    $options->additionalAuthenticatedData,
                ),
                $this->algorithm,
            );
            if (strlen($result->value) > self::MAX_PLAINTEXT_BYTES) {
                throw new DecryptionException('Envelope plaintext exceeds the 8 MiB protected-value size bound.');
            }

            return $result;
        } finally {
            sodium_memzero($dataKey);
        }
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
            throw new DecryptionException('Envelope key id is required for KeyRing decryption.');
        }

        $entry = $keyRing->resolveForRead(
            $keyId,
            KeyPurpose::ENVELOPE_PROTECTION,
            $this->algorithm->value,
        );
        if ($entry === null) {
            throw new DecryptionException('Envelope key id is not eligible for decryption.');
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
