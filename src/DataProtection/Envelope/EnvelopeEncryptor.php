<?php

namespace Infocyph\Epicrypt\DataProtection\Envelope;

use Infocyph\Epicrypt\Crypto\SecretBox\Encryptor as SecretBoxEncryptor;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Internal\Json;

final readonly class EnvelopeEncryptor
{
    public function __construct(
        private SecretBoxEncryptor $encryptor = new SecretBoxEncryptor(),
        private KeyMaterialGenerator $keyGenerator = new KeyMaterialGenerator(),
    ) {}

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
            'encrypted_data' => $this->encryptor->encrypt($plaintext, $dataKey),
            'encrypted_key' => $this->encryptor->encrypt($dataKey, $masterKey),
        ];
    }
}
