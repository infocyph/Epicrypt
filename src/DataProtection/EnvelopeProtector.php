<?php

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
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

            if (isset($envelope['v']) && (! is_numeric($envelope['v']) || (int) $envelope['v'] !== SecurityPolicy::ENVELOPE_FORMAT_VERSION)) {
                throw new DecryptionException('Unsupported envelope format version.');
            }

            if (isset($envelope['alg']) && (! is_string($envelope['alg']) || $envelope['alg'] !== SecurityPolicy::ENVELOPE_ALGORITHM)) {
                throw new DecryptionException('Unsupported envelope algorithm.');
            }

            $dataKey = $this->cipher->decrypt((string) ($envelope['encrypted_key'] ?? ''), $masterKey);

            return $this->cipher->decrypt((string) ($envelope['encrypted_data'] ?? ''), $dataKey);
        } catch (DecryptionException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @param array{encrypted_data: string, encrypted_key: string, v?: int, alg?: string} $envelope
     */
    public function encodeEnvelope(array $envelope): string
    {
        $envelope['v'] = (int) ($envelope['v'] ?? SecurityPolicy::ENVELOPE_FORMAT_VERSION);
        $envelope['alg'] = (string) ($envelope['alg'] ?? SecurityPolicy::ENVELOPE_ALGORITHM);

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
                'v' => SecurityPolicy::ENVELOPE_FORMAT_VERSION,
                'alg' => SecurityPolicy::ENVELOPE_ALGORITHM,
                'encrypted_data' => $this->cipher->encrypt($plaintext, $dataKey),
                'encrypted_key' => $this->cipher->encrypt($dataKey, $masterKey),
            ];
        } catch (Throwable $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        }
    }
}
