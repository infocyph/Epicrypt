<?php

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Internal\Json;

final readonly class EnvelopeProtector
{
    public function __construct(
        private SecretBoxCipher $cipher = new SecretBoxCipher(),
        private KeyMaterialGenerator $keyGenerator = new KeyMaterialGenerator(),
    ) {}

    public function decrypt(string $encodedEnvelope, string $masterKey): string
    {
        $envelope = Json::decodeToArray($encodedEnvelope);
        $dataKey = $this->cipher->decrypt((string) ($envelope['encrypted_key'] ?? ''), $masterKey);

        return $this->cipher->decrypt((string) ($envelope['encrypted_data'] ?? ''), $dataKey);
    }

    /**
     * @param array{encrypted_data: string, encrypted_key: string} $envelope
     */
    public function encodeEnvelope(array $envelope): string
    {
        return Json::encode($envelope);
    }

    /**
     * @return array{encrypted_data: string, encrypted_key: string}
     */
    public function encrypt(string $plaintext, string $masterKey): array
    {
        $dataKey = $this->keyGenerator->generate();

        return [
            'encrypted_data' => $this->cipher->encrypt($plaintext, $dataKey),
            'encrypted_key' => $this->cipher->encrypt($dataKey, $masterKey),
        ];
    }
}
