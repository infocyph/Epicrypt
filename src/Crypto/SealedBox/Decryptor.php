<?php

namespace Infocyph\Epicrypt\Crypto\SealedBox;

use Infocyph\Epicrypt\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class Decryptor implements DecryptorInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException('Recipient keypair must be a non-empty string.');
        }

        $keypair = (bool) ($context['key_is_binary'] ?? false) ? $key : Base64Url::decode($key);
        if (strlen($keypair) !== SODIUM_CRYPTO_BOX_KEYPAIRBYTES) {
            throw new InvalidKeyException('Recipient keypair has invalid length.');
        }

        $plaintext = sodium_crypto_box_seal_open(Base64Url::decode($ciphertext), $keypair);
        if (! is_string($plaintext)) {
            throw new DecryptionException('Sealed-box decryption failed.');
        }

        return $plaintext;
    }
}
