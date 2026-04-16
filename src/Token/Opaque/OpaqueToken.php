<?php

namespace Infocyph\Epicrypt\Token\Opaque;

use Infocyph\Epicrypt\Token\Contract\OpaqueTokenInterface;

final class OpaqueToken implements OpaqueTokenInterface
{
    public function hash(string $token): string
    {
        return sodium_bin2hex(sodium_crypto_generichash($token));
    }

    public function issue(int $length = 48): string
    {
        $bytes = random_bytes((int) ceil(($length * 3) / 4));
        $encoded = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

        return substr($encoded, 0, $length);
    }

    public function verify(string $token, string $digest): bool
    {
        return hash_equals($digest, $this->hash($token));
    }
}
