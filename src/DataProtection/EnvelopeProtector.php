<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyPurpose;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Enum\EnvelopeAlgorithm;
use Infocyph\Epicrypt\Internal\Enum\EnvelopeVersion;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
use Throwable;

final readonly class EnvelopeProtector
{
    public function __construct(
        private SecretBoxCipher $cipher = new SecretBoxCipher(),
        private KeyMaterialGenerator $keyGenerator = new KeyMaterialGenerator(),
        private SecurityProfile $profile = SecurityProfile::MODERN,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public static function forProfile(SecurityProfile $profile = SecurityProfile::MODERN): self
    {
        return new self(profile: $profile);
    }

    public function decrypt(string $encodedEnvelope, string $masterKey): string
    {
        try {
            $envelope = $this->decodeEnvelope($encodedEnvelope);
            $encryptedKey = $envelope['encrypted_key'];
            $encryptedData = $envelope['encrypted_data'];

            $dataKey = $this->cipher->decrypt($encryptedKey, $masterKey);

            return $this->cipher->decrypt($encryptedData, $dataKey);
        } catch (DecryptionException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $masterKeys
     */
    public function decryptWithAnyKey(string $encodedEnvelope, iterable|KeyRing $masterKeys): string
    {
        return $this->decryptWithAnyKeyResult($encodedEnvelope, $masterKeys)->plaintext;
    }

    /**
     * @param iterable<string, string>|KeyRing $masterKeys
     */
    public function decryptWithAnyKeyResult(string $encodedEnvelope, iterable|KeyRing $masterKeys): EnvelopeDecryptResult
    {
        $metadata = $this->decodeEnvelope($encodedEnvelope);

        if ($masterKeys instanceof KeyRing) {
            $keyId = $metadata['kid'] ?? null;
            if ($keyId !== null) {
                if (!is_string($keyId) || $keyId === '') {
                    throw new DecryptionException('Envelope kid must be a non-empty string when provided.');
                }

                $key = $masterKeys->keys()[$keyId] ?? null;
                if ($key === null) {
                    throw new DecryptionException(sprintf('Envelope key id "%s" was not found in the key ring.', $keyId));
                }

                try {
                    return new EnvelopeDecryptResult(
                        $this->decrypt($encodedEnvelope, $key),
                        $keyId,
                        false,
                        $this->stringOrNull($metadata['alg'] ?? null),
                        $this->stringOrNull($metadata['dek_alg'] ?? null),
                        $this->intOrNull($metadata['created_at'] ?? null),
                        $this->stringOrNull($metadata['purpose'] ?? null),
                    );
                } catch (DecryptionException $e) {
                    throw new DecryptionException(sprintf('Unable to decrypt envelope with key id "%s".', $keyId), 0, $e);
                }
            }
        }

        $lastException = null;
        foreach ($this->orderedKeyEntries($masterKeys) as $entry) {
            try {
                return new EnvelopeDecryptResult(
                    $this->decrypt($encodedEnvelope, $entry['key']),
                    $entry['id'],
                    !$entry['active'],
                    $this->stringOrNull($metadata['alg'] ?? null),
                    $this->stringOrNull($metadata['dek_alg'] ?? null),
                    $this->intOrNull($metadata['created_at'] ?? null),
                    $this->stringOrNull($metadata['purpose'] ?? null),
                );
            } catch (DecryptionException $e) {
                $lastException = $e;
            }
        }

        throw new DecryptionException('Unable to decrypt envelope with any supplied master key.', 0, $lastException);
    }

    public function decryptWithKeyRing(string $encodedEnvelope, KeyRing $masterKeys): string
    {
        return $this->decryptWithKeyRingResult($encodedEnvelope, $masterKeys)->plaintext;
    }

    public function decryptWithKeyRingResult(string $encodedEnvelope, KeyRing $masterKeys): EnvelopeDecryptResult
    {
        return $this->decryptWithAnyKeyResult($encodedEnvelope, $masterKeys);
    }

    /**
     * @param array{encrypted_data: string, encrypted_key: string, v?: int, alg?: string, kid?: ?string, dek_alg?: ?string, created_at?: ?int, purpose?: ?string} $envelope
     */
    public function encodeEnvelope(array $envelope): string
    {
        $envelope['v'] = (int) ($envelope['v'] ?? EnvelopeVersion::V1->value);
        $envelope['alg'] = (string) ($envelope['alg'] ?? EnvelopeAlgorithm::SECRETBOX->value);
        $envelope['dek_alg'] = (string) ($envelope['dek_alg'] ?? EnvelopeAlgorithm::SECRETBOX->value);
        $envelope['created_at'] = (int) ($envelope['created_at'] ?? $this->clock->now());

        return Json::encode($envelope);
    }

    /**
     * @param array{purpose?: mixed} $context
     * @return array{encrypted_data: string, encrypted_key: string, v: int, alg: string, dek_alg: string, created_at: int, purpose?: string, kid?: ?string}
     */
    public function encrypt(string $plaintext, string $masterKey, array $context = []): array
    {
        try {
            $dataKey = $this->keyGenerator->forPurpose(KeyPurpose::SECRETBOX, $this->profile);
            $purpose = $context['purpose'] ?? null;
            if ($purpose !== null && (!is_string($purpose) || $purpose === '')) {
                throw new EncryptionException('Envelope purpose must be a non-empty string when provided.');
            }

            $envelope = [
                'v' => EnvelopeVersion::V1->value,
                'alg' => EnvelopeAlgorithm::SECRETBOX->value,
                'dek_alg' => EnvelopeAlgorithm::SECRETBOX->value,
                'created_at' => $this->clock->now(),
                'encrypted_data' => $this->cipher->encrypt($plaintext, $dataKey),
                'encrypted_key' => $this->cipher->encrypt($dataKey, $masterKey),
            ];
            if ($purpose !== null) {
                $envelope['purpose'] = $purpose;
            }

            return $envelope;
        } catch (Throwable $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @param array{purpose?: mixed} $context
     * @return array{encrypted_data: string, encrypted_key: string, v: int, alg: string, dek_alg: string, created_at: int, purpose?: string, kid: string}
     */
    public function encryptWithKeyRing(string $plaintext, KeyRing $masterKeys, array $context = []): array
    {
        $activeKey = $masterKeys->activeKey();
        $activeKeyId = $masterKeys->activeKeyId();
        if ($activeKey === null || $activeKeyId === null) {
            throw new ConfigurationException('Key ring active key id is required for envelope encryption.');
        }

        $envelope = $this->encrypt($plaintext, $activeKey, $context);
        $envelope['kid'] = $activeKeyId;

        return $envelope;
    }

    public function inspect(string $encodedEnvelope): EnvelopeInspectResult
    {
        $envelope = $this->decodeEnvelope($encodedEnvelope);

        return new EnvelopeInspectResult(
            version: isset($envelope['v']) && is_numeric($envelope['v']) ? (int) $envelope['v'] : EnvelopeVersion::V1->value,
            algorithm: $this->stringOrNull($envelope['alg'] ?? null) ?? EnvelopeAlgorithm::SECRETBOX->value,
            keyId: $this->stringOrNull($envelope['kid'] ?? null),
            dekAlgorithm: $this->stringOrNull($envelope['dek_alg'] ?? null),
            createdAt: $this->intOrNull($envelope['created_at'] ?? null),
            purpose: $this->stringOrNull($envelope['purpose'] ?? null),
        );
    }

    public function needsReencrypt(string $encodedEnvelope, ?string $activeKeyId = null, ?int $maxAgeSeconds = null): bool
    {
        $info = $this->inspect($encodedEnvelope);

        if ($this->needsRotation($encodedEnvelope, $activeKeyId)) {
            return true;
        }

        if ($info->dekAlgorithm === null || !hash_equals($info->dekAlgorithm, EnvelopeAlgorithm::SECRETBOX->value)) {
            return true;
        }

        if ($maxAgeSeconds !== null && $maxAgeSeconds > 0) {
            if ($info->createdAt === null) {
                return true;
            }

            if ($this->clock->now() - $info->createdAt > $maxAgeSeconds) {
                return true;
            }
        }

        return false;
    }

    public function needsRotation(string $encodedEnvelope, ?string $activeKeyId = null): bool
    {
        if ($activeKeyId === null || $activeKeyId === '') {
            return false;
        }

        $info = $this->inspect($encodedEnvelope);

        return $info->keyId === null || !hash_equals($activeKeyId, $info->keyId);
    }

    public function reencrypt(string $encodedEnvelope, string $oldMasterKey, string $newMasterKey): string
    {
        $plaintext = $this->decrypt($encodedEnvelope, $oldMasterKey);

        return $this->encodeEnvelope($this->encrypt($plaintext, $newMasterKey));
    }

    /**
     * @param iterable<string, string>|KeyRing $masterKeys
     */
    public function reencryptWithAnyKey(string $encodedEnvelope, iterable|KeyRing $masterKeys, string $newMasterKey): string
    {
        $plaintext = $this->decryptWithAnyKeyResult($encodedEnvelope, $masterKeys)->plaintext;

        return $this->encodeEnvelope($this->encrypt($plaintext, $newMasterKey));
    }

    public function reencryptWithKeyRing(string $encodedEnvelope, KeyRing $masterKeys): string
    {
        $plaintext = $this->decryptWithKeyRingResult($encodedEnvelope, $masterKeys)->plaintext;

        return $this->encodeEnvelope($this->encryptWithKeyRing($plaintext, $masterKeys));
    }

    /**
     * @param array<string, mixed> $envelope
     */
    private function assertEnvelopeMetadata(array $envelope): void
    {
        if (isset($envelope['v']) && (!is_numeric($envelope['v']) || (int) $envelope['v'] !== EnvelopeVersion::V1->value)) {
            throw new DecryptionException('Unsupported envelope format version.');
        }

        if (isset($envelope['alg']) && (!is_string($envelope['alg']) || $envelope['alg'] !== EnvelopeAlgorithm::SECRETBOX->value)) {
            throw new DecryptionException('Unsupported envelope algorithm.');
        }

        if (isset($envelope['dek_alg']) && (!is_string($envelope['dek_alg']) || $envelope['dek_alg'] === '')) {
            throw new DecryptionException('Envelope dek_alg must be a non-empty string when provided.');
        }

        if (isset($envelope['created_at']) && !is_numeric($envelope['created_at'])) {
            throw new DecryptionException('Envelope created_at must be a numeric timestamp when provided.');
        }

        if (isset($envelope['purpose']) && (!is_string($envelope['purpose']) || $envelope['purpose'] === '')) {
            throw new DecryptionException('Envelope purpose must be a non-empty string when provided.');
        }
    }

    /**
     * @return array{encrypted_data: string, encrypted_key: string, v?: mixed, alg?: mixed, kid?: mixed, dek_alg?: mixed, created_at?: mixed, purpose?: mixed}
     */
    private function decodeEnvelope(string $encodedEnvelope): array
    {
        $envelope = Json::decodeToArray($encodedEnvelope);
        $this->assertEnvelopeMetadata($envelope);
        $encryptedKey = $this->requireNonEmptyEnvelopeString($envelope, 'encrypted_key');
        $encryptedData = $this->requireNonEmptyEnvelopeString($envelope, 'encrypted_data');

        return $this->projectDecodedEnvelope($envelope, $encryptedData, $encryptedKey);
    }

    private function intOrNull(mixed $value): ?int
    {
        return is_numeric($value) ? (int) $value : null;
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<array{id: ?string, key: string, active: bool}>
     */
    private function orderedKeyEntries(iterable|KeyRing $keys): array
    {
        try {
            return KeyCandidates::orderedEntries(
                $keys,
                'All master key candidates must be non-empty strings.',
                'At least one master key candidate is required.',
            );
        } catch (\InvalidArgumentException $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @param array<string, mixed> $envelope
     * @return array{encrypted_data: string, encrypted_key: string, v?: mixed, alg?: mixed, kid?: mixed, dek_alg?: mixed, created_at?: mixed, purpose?: mixed}
     */
    private function projectDecodedEnvelope(array $envelope, string $encryptedData, string $encryptedKey): array
    {
        $result = ['encrypted_data' => $encryptedData, 'encrypted_key' => $encryptedKey];
        foreach (['v', 'alg', 'kid', 'dek_alg', 'created_at', 'purpose'] as $key) {
            if (array_key_exists($key, $envelope)) {
                $result[$key] = $envelope[$key];
            }
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $envelope
     */
    private function requireNonEmptyEnvelopeString(array $envelope, string $field): string
    {
        $value = $envelope[$field] ?? null;
        if (!is_string($value) || $value === '') {
            throw new DecryptionException(sprintf('Envelope %s must be a non-empty string.', $field));
        }

        return $value;
    }

    private function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
