<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Payload;

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyVerificationResult;
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
    public function decode(
        #[\SensitiveParameter]
        string $token,
        #[\SensitiveParameter]
        string $key,
    ): array {
        return new SignedPayloadCodec($key, clock: $this->clock)->verify($token, $this->context);
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return array<string, mixed>
     */
    public function decodeWithAnyKey(
        #[\SensitiveParameter]
        string $token,
        #[\SensitiveParameter]
        iterable|KeyRing $keys,
    ): array {
        $lastException = null;
        foreach ($this->orderedKeys($keys) as $candidateKey) {
            try {
                return $this->decode($token, $candidateKey);
            } catch (\Throwable $exception) {
                $lastException = $exception;
            }
        }

        throw new TokenException(
            'Signed payload verification failed for every supplied key.',
            0,
            $lastException,
        );
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function encode(
        #[\SensitiveParameter]
        array $claims,
        #[\SensitiveParameter]
        string $key,
        ?int $expiresAt = null,
    ): string {
        return new SignedPayloadCodec($key, clock: $this->clock)->issue(
            $claims,
            $expiresAt,
            $this->context,
        );
    }

    public function verify(
        #[\SensitiveParameter]
        string $token,
        #[\SensitiveParameter]
        string $key,
    ): bool {
        return $this->verifyResult($token, $key)->verified;
    }

    public function verifyResult(
        #[\SensitiveParameter]
        string $token,
        #[\SensitiveParameter]
        string $key,
    ): SignedPayloadVerificationResult {
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
    public function verifyWithAnyKey(
        #[\SensitiveParameter]
        string $token,
        #[\SensitiveParameter]
        iterable|KeyRing $keys,
    ): bool {
        return $this->verifyWithAnyKeyDetailedResult($token, $keys)->verified;
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    public function verifyWithAnyKeyDetailedResult(
        #[\SensitiveParameter]
        string $token,
        #[\SensitiveParameter]
        iterable|KeyRing $keys,
    ): SignedPayloadVerificationResult {
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
    public function verifyWithAnyKeyResult(
        #[\SensitiveParameter]
        string $token,
        #[\SensitiveParameter]
        iterable|KeyRing $keys,
    ): KeyVerificationResult {
        foreach ($this->orderedKeyEntries($keys) as $entry) {
            if ($this->verify($token, $entry['key'])) {
                return new KeyVerificationResult(true, $entry['id'], !$entry['active']);
            }
        }

        return new KeyVerificationResult(false);
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<array{id: ?string, key: string, active: bool}>
     */
    private function orderedKeyEntries(#[\SensitiveParameter] iterable|KeyRing $keys): array
    {
        try {
            return KeyCandidates::orderedEntries(
                $keys,
                'All signed payload key candidates must be non-empty strings.',
                'At least one signed payload key candidate is required.',
                KeyPurpose::SIGNED_PAYLOAD,
                'sha512',
            );
        } catch (\InvalidArgumentException $exception) {
            throw new TokenException($exception->getMessage(), 0, $exception);
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<string>
     */
    private function orderedKeys(#[\SensitiveParameter] iterable|KeyRing $keys): array
    {
        return array_column($this->orderedKeyEntries($keys), 'key');
    }
}
