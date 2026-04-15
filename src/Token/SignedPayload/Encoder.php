<?php

namespace Infocyph\Epicrypt\Token\SignedPayload;

use Infocyph\Epicrypt\Contract\TokenEncoderInterface;
use Infocyph\Epicrypt\Security\Support\SignedPayloadCodec;

final readonly class Encoder implements TokenEncoderInterface
{
    public function __construct(
        private ?string $context = null,
    ) {}

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    public function encode(array $claims, mixed $key, array $headers = []): string
    {
        return new SignedPayloadCodec((string) $key)->issue(
            $claims,
            isset($headers['exp']) && is_numeric($headers['exp']) ? (int) $headers['exp'] : null,
            $this->context,
        );
    }
}
