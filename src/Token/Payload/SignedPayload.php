<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Payload;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\KeyRing;
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
     * @param iterable<string, string>|KeyRing $keys
     * @return array<string, mixed>
     */
    public function decodeWithAnyKey(string $token, iterable|KeyRing $keys): array
    {
        $lastException = null;
        foreach ($this->orderedKeys($keys) as $key) {
            try {
                return $this->decode($token, $key);
            } catch (TokenException $e) {
                $lastException = $e;
            }
        }

        throw new TokenException('Signed payload verification failed for every supplied key.', 0, $lastException);
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

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    public function verifyWithAnyKey(string $token, iterable|KeyRing $keys): bool
    {
        try {
            $this->decodeWithAnyKey($token, $keys);

            return true;
        } catch (TokenException) {
            return false;
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<string>
     */
    private function orderedKeys(iterable|KeyRing $keys): array
    {
        try {
            return KeyCandidates::ordered(
                $keys,
                'All signed payload key candidates must be non-empty strings.',
                'At least one signed payload key candidate is required.',
            );
        } catch (\InvalidArgumentException $e) {
            throw new TokenException($e->getMessage(), 0, $e);
        }
    }
}
