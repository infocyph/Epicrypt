<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Payload;

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyVerificationResult;
use Infocyph\Epicrypt\Token\Support\TokenAnyKey;
use Infocyph\Epicrypt\Token\Support\TokenKeyCandidates;
use Psr\Clock\ClockInterface;

final readonly class SignedPayload
{
    public function __construct(
        private ?string $context = null,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function decode(string $token, mixed $key): array
    {
        if (!is_string($key) || $key === '') {
            throw new TokenException('Signed payload key must be a non-empty string.');
        }

        return new SignedPayloadCodec($key, clock: $this->clock)->verify($token, $this->context);
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

        return new SignedPayloadCodec($key, clock: $this->clock)->issue(
            $claims,
            isset($headers['exp']) && is_numeric($headers['exp']) ? (int) $headers['exp'] : null,
            $this->context,
        );
    }

    public function verify(string $token, mixed $key): bool
    {
        return $this->verifyResult($token, $key)->verified;
    }

    public function verifyResult(string $token, mixed $key): SignedPayloadVerificationResult
    {
        try {
            $claims = $this->decode($token, $key);

            return new SignedPayloadVerificationResult(true, $claims);
        } catch (ExpiredTokenException) {
            return new SignedPayloadVerificationResult(false, expired: true);
        } catch (TokenException) {
            return new SignedPayloadVerificationResult(false);
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    public function verifyWithAnyKey(string $token, iterable|KeyRing $keys): bool
    {
        return $this->verifyWithAnyKeyDetailedResult($token, $keys)->verified;
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    public function verifyWithAnyKeyDetailedResult(string $token, iterable|KeyRing $keys): SignedPayloadVerificationResult
    {
        $lastResult = new SignedPayloadVerificationResult(false);
        foreach ($this->orderedKeyEntries($keys) as $entry) {
            $result = $this->verifyResult($token, $entry['key']);
            if ($result->verified) {
                return new SignedPayloadVerificationResult(
                    true,
                    $result->claims,
                    $entry['id'],
                    !$entry['active'],
                    $result->expired,
                );
            }
            $lastResult = $result;
        }

        return $lastResult;
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
            KeyPurpose::SIGNED_PAYLOAD,
            'sha512',
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
            KeyPurpose::SIGNED_PAYLOAD,
            'sha512',
        );
    }
}
