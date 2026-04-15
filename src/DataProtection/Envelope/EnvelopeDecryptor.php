<?php

namespace Infocyph\Epicrypt\DataProtection\Envelope;

use Infocyph\Epicrypt\Crypto\SecretBox\Decryptor as SecretBoxDecryptor;
use Infocyph\Epicrypt\Internal\Json;

final readonly class EnvelopeDecryptor
{
    public function __construct(
        private SecretBoxDecryptor $decryptor = new SecretBoxDecryptor(),
    ) {}

    public function decrypt(string $encodedEnvelope, string $masterKey): string
    {
        $envelope = Json::decodeToArray($encodedEnvelope);

        $dataKey = $this->decryptor->decrypt((string) ($envelope['encrypted_key'] ?? ''), $masterKey);

        return $this->decryptor->decrypt((string) ($envelope['encrypted_data'] ?? ''), $dataKey);
    }
}
