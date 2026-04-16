<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Opaque;

use Infocyph\Epicrypt\Generate\Support\LengthGuard;
use Infocyph\Epicrypt\Token\Contract\OpaqueTokenInterface;

final class OpaqueToken implements OpaqueTokenInterface
{
    public function hash(string $token): string
    {
        return sodium_bin2hex(sodium_crypto_generichash($token));
    }

    public function issue(int $length = 48): string
    {
        $safeLength = LengthGuard::atLeastOne($length, 'Opaque token length');
        $byteLength = LengthGuard::atLeastOne((int) ceil(($safeLength * 3) / 4), 'Opaque token byte length');
        $bytes = random_bytes($byteLength);
        $encoded = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

        return substr($encoded, 0, $safeLength);
    }

    public function verify(string $token, string $digest): bool
    {
        return hash_equals($digest, $this->hash($token));
    }
}
