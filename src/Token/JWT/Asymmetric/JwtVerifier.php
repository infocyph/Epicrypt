<?php

namespace Infocyph\Epicrypt\Token\JWT\Asymmetric;

use ArrayAccess;
use Infocyph\Epicrypt\Contract\TokenVerifierInterface;
use Infocyph\Epicrypt\Token\JWT\Validation\RegisteredClaims;

final readonly class JwtVerifier implements TokenVerifierInterface
{
    private JwtDecoder $decoder;

    public function __construct(
        RegisteredClaims $expectedClaims,
        ?string $passphrase = null,
        string $algorithm = 'RS512',
    ) {
        $this->decoder = new JwtDecoder($expectedClaims, $passphrase, $algorithm);
    }

    /**
     * @param string|array<string, mixed>|ArrayAccess<string, mixed> $key
     */
    public function verify(string $token, mixed $key): bool
    {
        try {
            $this->decoder->decode($token, $key);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }
}
