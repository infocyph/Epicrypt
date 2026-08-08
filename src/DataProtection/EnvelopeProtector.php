<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Psr\Clock\ClockInterface;

final readonly class EnvelopeProtector
{
    private const string CONTENT_DOMAIN = 'envelope-content';

    private const string DOMAIN = 'envelope';

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
        string $masterKey,
        ProtectionOptions $options,
    ): string {
        return $this->protectResult($plaintext, $masterKey, $options)->value;
    }

    public function protectResult(
        string $plaintext,
        #[\SensitiveParameter]
        string $masterKey,
        ProtectionOptions $options,
    ): ProtectionResult {
        return $this->protectWithBinaryKeyResult($plaintext, Base64Url::decode($masterKey), $options);
    }

    public function protectWithBinaryKeyResult(
        string $plaintext,
        #[\SensitiveParameter]
        string $masterKey,
        ProtectionOptions $options,
    ): ProtectionResult {
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
        string $plaintext,
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
        string $payload,
        #[\SensitiveParameter]
        string $masterKey,
        ProtectionOptions $options,
    ): string {
        return $this->unprotectResult($payload, $masterKey, $options)->value;
    }

    public function unprotectResult(
        string $payload,
        #[\SensitiveParameter]
        string $masterKey,
        ProtectionOptions $options,
    ): ProtectionResult {
        return $this->unprotectWithBinaryKeyResult($payload, Base64Url::decode($masterKey), $options);
    }

    public function unprotectWithBinaryKeyResult(
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
            return ProtectedPayload::decrypt(
                $protectedContent,
                $dataKey,
                self::CONTENT_DOMAIN,
                new ProtectionOptions(
                    $options->purpose,
                    $options->additionalAuthenticatedData,
                ),
                $this->algorithm,
            );
        } finally {
            sodium_memzero($dataKey);
        }
    }

    public function unprotectWithKeyRing(
        string $payload,
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

        return $this->unprotectResult($payload, $entry->key, $options);
    }
}
