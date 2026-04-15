<?php

namespace Infocyph\Epicrypt\Token\SignedPayload;

use Infocyph\Epicrypt\Contract\TokenDecoderInterface;
use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

final readonly class Decoder implements TokenDecoderInterface
{
    public function __construct(
        private ?string $context = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function decode(string $token, mixed $key): array
    {
        return new SignedPayloadCodec((string) $key)->verify($token, $this->context);
    }
}
