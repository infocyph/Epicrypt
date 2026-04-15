<?php

namespace Infocyph\Epicrypt\Token\SignedPayload;

use Infocyph\Epicrypt\Contract\TokenVerifierInterface;
use Infocyph\Epicrypt\Exception\Token\TokenException;

final readonly class Verifier implements TokenVerifierInterface
{
    public function __construct(
        private Decoder $decoder = new Decoder(),
    ) {}

    public function verify(string $token, mixed $key): bool
    {
        try {
            $this->decoder->decode($token, $key);

            return true;
        } catch (TokenException) {
            return false;
        }
    }
}
