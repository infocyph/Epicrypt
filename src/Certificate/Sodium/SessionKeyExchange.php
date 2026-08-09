<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Sodium;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\BinaryKey;

final class SessionKeyExchange implements KeyExchangeInterface
{
    public function clientSessionKeys(
        #[\SensitiveParameter]
        string $clientKeyPair,
        string $serverPublicKey,
    ): DirectionalSessionKeys {
        $this->validateKxInputs($clientKeyPair, $serverPublicKey);
        [$receive, $transmit] = sodium_crypto_kx_client_session_keys($clientKeyPair, $serverPublicKey);

        return new DirectionalSessionKeys($receive, $transmit);
    }

    public function deriveSharedSecret(string $privateKey, string $publicKey, bool $keysAreBinary): string
    {
        try {
            $private = BinaryKey::fixedLength($privateKey, $keysAreBinary, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 'Private key');
            $public = BinaryKey::fixedLength($publicKey, $keysAreBinary, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'Public key');
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException('Sodium key exchange requires valid curve25519 private/public keys.', 0, $e);
        }

        return sodium_crypto_scalarmult($private, $public);
    }

    public function generateKeyPair(): string
    {
        return sodium_crypto_kx_keypair();
    }

    public function serverSessionKeys(
        #[\SensitiveParameter]
        string $serverKeyPair,
        string $clientPublicKey,
    ): DirectionalSessionKeys {
        $this->validateKxInputs($serverKeyPair, $clientPublicKey);
        [$receive, $transmit] = sodium_crypto_kx_server_session_keys($serverKeyPair, $clientPublicKey);

        return new DirectionalSessionKeys($receive, $transmit);
    }

    private function validateKxInputs(string $keyPair, string $peerPublicKey): void
    {
        if (strlen($keyPair) !== SODIUM_CRYPTO_KX_KEYPAIRBYTES || strlen($peerPublicKey) !== SODIUM_CRYPTO_KX_PUBLICKEYBYTES) {
            throw new InvalidKeyException('Sodium crypto_kx requires an exact keypair and peer public key.');
        }
    }
}
