<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Payload;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Token\Contract\PayloadTokenInterface;

final readonly class SignedPayload implements PayloadTokenInterface
{
    public function __construct(
        private ?string $context = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function decode(string $token, mixed $key): array
    {
        if (!is_string($key) || $key === '') {
            throw new TokenException('Signed payload key must be a non-empty string.');
        }

        return new SignedPayloadCodec($key)->verify($token, $this->context);
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    public function encode(array $claims, mixed $key, array $headers = []): string
    {
        if (!is_string($key) || $key === '') {
            throw new TokenException('Signed payload key must be a non-empty string.');
        }

        return new SignedPayloadCodec($key)->issue(
            $claims,
            isset($headers['exp']) && is_numeric($headers['exp']) ? (int) $headers['exp'] : null,
            $this->context,
        );
    }

    public function verify(string $token, mixed $key): bool
    {
        try {
            $this->decode($token, $key);

            return true;
        } catch (TokenException) {
            return false;
        }
    }
}
