<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Internal\Enum\EnvelopeAlgorithm;
use Infocyph\Epicrypt\Internal\Enum\EnvelopeVersion;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Security\KeyRing;
use Throwable;

final readonly class EnvelopeProtector
{
    public function __construct(
        private SecretBoxCipher $cipher = new SecretBoxCipher(),
        private KeyMaterialGenerator $keyGenerator = new KeyMaterialGenerator(),
    ) {}

    public function decrypt(string $encodedEnvelope, string $masterKey): string
    {
        try {
            $envelope = Json::decodeToArray($encodedEnvelope);

            if (isset($envelope['v']) && (!is_numeric($envelope['v']) || (int) $envelope['v'] !== EnvelopeVersion::V1->value)) {
                throw new DecryptionException('Unsupported envelope format version.');
            }

            if (isset($envelope['alg']) && (!is_string($envelope['alg']) || $envelope['alg'] !== EnvelopeAlgorithm::SECRETBOX->value)) {
                throw new DecryptionException('Unsupported envelope algorithm.');
            }

            $encryptedKey = $envelope['encrypted_key'] ?? null;
            if (!is_string($encryptedKey) || $encryptedKey === '') {
                throw new DecryptionException('Envelope encrypted_key must be a non-empty string.');
            }

            $encryptedData = $envelope['encrypted_data'] ?? null;
            if (!is_string($encryptedData) || $encryptedData === '') {
                throw new DecryptionException('Envelope encrypted_data must be a non-empty string.');
            }

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
    public function decryptWithAny(string $encodedEnvelope, iterable|KeyRing $masterKeys): string
    {
        $lastException = null;
        foreach ($this->orderedKeys($masterKeys) as $masterKey) {
            try {
                return $this->decrypt($encodedEnvelope, $masterKey);
            } catch (DecryptionException $e) {
                $lastException = $e;
            }
        }

        throw new DecryptionException('Unable to decrypt envelope with any supplied master key.', 0, $lastException);
    }

    /**
     * @param array{encrypted_data: string, encrypted_key: string, v?: int, alg?: string} $envelope
     */
    public function encodeEnvelope(array $envelope): string
    {
        $envelope['v'] = (int) ($envelope['v'] ?? EnvelopeVersion::V1->value);
        $envelope['alg'] = (string) ($envelope['alg'] ?? EnvelopeAlgorithm::SECRETBOX->value);

        return Json::encode($envelope);
    }

    /**
     * @return array{encrypted_data: string, encrypted_key: string, v: int, alg: string}
     */
    public function encrypt(string $plaintext, string $masterKey): array
    {
        try {
            $dataKey = $this->keyGenerator->generate();

            return [
                'v' => EnvelopeVersion::V1->value,
                'alg' => EnvelopeAlgorithm::SECRETBOX->value,
                'encrypted_data' => $this->cipher->encrypt($plaintext, $dataKey),
                'encrypted_key' => $this->cipher->encrypt($dataKey, $masterKey),
            ];
        } catch (Throwable $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        }
    }

    public function reencrypt(string $encodedEnvelope, string $oldMasterKey, string $newMasterKey): string
    {
        $plaintext = $this->decrypt($encodedEnvelope, $oldMasterKey);

        return $this->encodeEnvelope($this->encrypt($plaintext, $newMasterKey));
    }

    /**
     * @param iterable<string, string>|KeyRing $masterKeys
     */
    public function reencryptWithAny(string $encodedEnvelope, iterable|KeyRing $masterKeys, string $newMasterKey): string
    {
        $plaintext = $this->decryptWithAny($encodedEnvelope, $masterKeys);

        return $this->encodeEnvelope($this->encrypt($plaintext, $newMasterKey));
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<string>
     */
    private function orderedKeys(iterable|KeyRing $keys): array
    {
        try {
            return KeyCandidates::ordered(
                $keys,
                'All master key candidates must be non-empty strings.',
                'At least one master key candidate is required.',
            );
        } catch (\InvalidArgumentException $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        }
    }
}
