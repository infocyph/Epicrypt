<?php

namespace AbmmHasan\SafeGuard\Asymmetric\Sodium;

use SodiumException;

class SodiumSessionExchange
{
    public function __construct(
        private string $keypair,
    ) {}

    /**
     * @param $serverPublicKey
     * @return string[]
     * @throws SodiumException
     */
    public function getKeyPairForClient($serverPublicKey): array
    {
        return sodium_crypto_kx_client_session_keys($this->keypair, $serverPublicKey);
    }

    /**
     * @param $clientPublicKey
     * @return string[]
     * @throws SodiumException
     */
    public function getKeyPairForServer($clientPublicKey): array
    {
        return sodium_crypto_kx_server_session_keys($this->keypair, $clientPublicKey);
    }
}
