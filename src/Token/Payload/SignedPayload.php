<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Payload;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyVerificationResult;
use Infocyph\Epicrypt\Token\Contract\PayloadTokenInterface;
use Infocyph\Epicrypt\Token\Support\TokenAnyKey;
use Infocyph\Epicrypt\Token\Support\TokenKeyCandidates;

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
        return TokenAnyKey::decode(
            $this->orderedKeys($keys),
            fn(string $candidateKey): array => $this->decode($token, $candidateKey),
            fn(?\Throwable $previous): \Throwable => new TokenException(
                'Signed payload verification failed for every supplied key.',
                0,
                $previous,
            ),
        );
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
        return $this->verifyWithAnyKeyResult($token, $keys)->verified;
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    public function verifyWithAnyKeyResult(string $token, iterable|KeyRing $keys): KeyVerificationResult
    {
        return TokenAnyKey::verifyResult(
            $this->orderedKeyEntries($keys),
            fn(string $candidateKey): bool => $this->verify($token, $candidateKey),
        );
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<array{id: ?string, key: string, active: bool}>
     */
    private function orderedKeyEntries(iterable|KeyRing $keys): array
    {
        return TokenKeyCandidates::orderedEntries(
            $keys,
            'All signed payload key candidates must be non-empty strings.',
            'At least one signed payload key candidate is required.',
        );
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<string>
     */
    private function orderedKeys(iterable|KeyRing $keys): array
    {
        return TokenKeyCandidates::orderedKeys(
            $keys,
            'All signed payload key candidates must be non-empty strings.',
            'At least one signed payload key candidate is required.',
        );
    }
}
