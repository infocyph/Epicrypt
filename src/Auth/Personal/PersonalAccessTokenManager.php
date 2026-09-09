<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Auth\Token\AuthTokenClass;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class PersonalAccessTokenManager
{
    private const int STORAGE_ATTEMPTS = 3;

    public function __construct(
        private AsymmetricSigningKeySet $keys,
        private PersonalAccessTokenStoreInterface $store,
        private PersonalAccessTokenPolicy $policy,
        private ?PersonalAccessTokenUsageStoreInterface $usageStore = null,
        private ClockInterface $clock = new SystemClock(),
    ) {
        if ($this->keys->purpose !== KeyPurpose::API_PERSONAL_TOKEN_SIGNING) {
            throw new ConfigurationException('Personal-token signing keys must use the API personal-token key purpose.');
        }
        if ($this->usageStore !== null && $this->policy->lastUsedWriteIntervalSeconds === null) {
            throw new ConfigurationException('Personal-token usage storage requires a configured last-used write interval.');
        }
    }

    /** @param array<array-key, mixed> $abilities */
    public function issue(
        string $subject,
        string $name,
        array $abilities,
        ?int $expiresAt = null,
    ): PersonalAccessTokenIssue {
        AuthProtocolPolicy::assertText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Personal-token subject');
        AuthProtocolPolicy::assertText($name, AuthProtocolPolicy::MAX_PERSONAL_TOKEN_NAME_BYTES, 'Personal-token name');
        $abilitySet = new PersonalAccessTokenAbilities($abilities, $this->policy->wildcardPolicy);
        $now = $this->clock->now()->getTimestamp();
        $expiresAt = $this->policy->expiresAt($now, $expiresAt);
        $ttl = $expiresAt - $now;

        for ($attempt = 0; $attempt < self::STORAGE_ATTEMPTS; $attempt++) {
            $claims = JwtClaims::issue(
                issuer: $this->keys->issuer,
                subject: $subject,
                audiences: [$this->policy->audience],
                ttlSeconds: $ttl,
                custom: [
                    'token_use' => 'personal_access_token',
                    'name' => $name,
                    'abilities' => $abilitySet->values,
                ],
                clock: $this->clock,
            );
            $record = new PersonalAccessTokenRecord(
                tokenId: $claims->jwtId,
                subject: $subject,
                name: $name,
                abilities: $abilitySet->values,
                createdAt: $claims->issuedAt,
                expiresAt: $claims->expiresAt,
            );
            if (!$this->store->create($record)) {
                continue;
            }

            return new PersonalAccessTokenIssue($this->sign($claims), $record);
        }

        throw new ConfigurationException('Unable to persist a unique personal access token.');
    }

    /** @return list<PersonalAccessTokenRecord> */
    public function list(string $subject, int $limit = 100): array
    {
        AuthProtocolPolicy::assertText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Personal-token subject');

        return $this->store->listForSubject($subject, $limit);
    }

    public function revoke(string $tokenId, string $subject): ?PersonalAccessTokenRecord
    {
        AuthProtocolPolicy::assertText($tokenId, 128, 'Personal-token ID');
        AuthProtocolPolicy::assertText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Personal-token subject');

        return $this->store->revoke($tokenId, $subject, $this->clock->now()->getTimestamp());
    }

    public function revokeAll(string $subject): int
    {
        AuthProtocolPolicy::assertText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Personal-token subject');

        return $this->store->revokeAll($subject, $this->clock->now()->getTimestamp());
    }

    public function verify(#[\SensitiveParameter] string $token): PersonalAccessTokenValidationResult
    {
        $verified = AsymmetricJwt::verifier(
            publicKey: $this->keys->publicKeys(),
            policy: JwtPolicy::personalAccessToken(
                $this->keys->issuer,
                $this->policy->audience,
                $this->policy->maximumLifetimeSeconds,
            ),
            algorithm: $this->keys->algorithm,
            clock: $this->clock,
        )->verifyResult($token);
        if (!$verified->valid) {
            return PersonalAccessTokenValidationResult::invalid($verified->failureReason);
        }

        try {
            $state = $this->claimState($verified->claims);
        } catch (Throwable) {
            return PersonalAccessTokenValidationResult::stateMismatch();
        }

        $record = $this->store->find($state['token_id']);
        $now = $this->clock->now()->getTimestamp();
        if (!$record instanceof PersonalAccessTokenRecord || !$record->isActive($now)) {
            return PersonalAccessTokenValidationResult::inactive();
        }
        if (!$this->recordMatches($record, $state)) {
            return PersonalAccessTokenValidationResult::stateMismatch();
        }

        $abilities = new PersonalAccessTokenAbilities($record->abilities, $this->policy->wildcardPolicy);
        $lastUsedAt = $this->recordUsage($record, $now);

        return PersonalAccessTokenValidationResult::valid($record, $abilities, $lastUsedAt);
    }

    /**
     * @param array<string, mixed> $claims
     * @return array{token_id:string,subject:string,name:string,abilities:list<string>,created_at:int,expires_at:int}
     */
    private function claimState(array $claims): array
    {
        $tokenId = $claims['jti'] ?? null;
        $subject = $claims['sub'] ?? null;
        $name = $claims['name'] ?? null;
        $abilities = $claims['abilities'] ?? null;
        $createdAt = $claims['iat'] ?? null;
        $expiresAt = $claims['exp'] ?? null;
        if (($claims['token_use'] ?? null) !== 'personal_access_token'
            || !is_string($tokenId)
            || !is_string($subject)
            || !is_string($name)
            || !is_array($abilities)
            || !is_int($createdAt)
            || !is_int($expiresAt)) {
            throw new ConfigurationException('Personal-token JWT state claims are invalid.');
        }
        AuthProtocolPolicy::assertText($tokenId, 128, 'Personal-token ID');
        AuthProtocolPolicy::assertText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Personal-token subject');
        AuthProtocolPolicy::assertText($name, AuthProtocolPolicy::MAX_PERSONAL_TOKEN_NAME_BYTES, 'Personal-token name');
        $abilitySet = new PersonalAccessTokenAbilities($abilities, $this->policy->wildcardPolicy);

        return [
            'token_id' => $tokenId,
            'subject' => $subject,
            'name' => $name,
            'abilities' => $abilitySet->values,
            'created_at' => $createdAt,
            'expires_at' => $expiresAt,
        ];
    }

    /** @param array{token_id:string,subject:string,name:string,abilities:list<string>,created_at:int,expires_at:int} $state */
    private function recordMatches(PersonalAccessTokenRecord $record, array $state): bool
    {
        return hash_equals($record->tokenId, $state['token_id'])
            && hash_equals($record->subject, $state['subject'])
            && hash_equals($record->name, $state['name'])
            && $record->abilities === $state['abilities']
            && $record->createdAt === $state['created_at']
            && $record->expiresAt === $state['expires_at'];
    }

    private function recordUsage(PersonalAccessTokenRecord $record, int $usedAt): ?int
    {
        $interval = $this->policy->lastUsedWriteIntervalSeconds;
        if ($this->usageStore === null || $interval === null) {
            return null;
        }

        return $this->usageStore->touch($record->tokenId, $record->subject, $usedAt, $interval);
    }

    private function sign(JwtClaims $claims): string
    {
        return AsymmetricJwt::issuer(
            privateKey: $this->keys->privateKey(),
            type: AuthTokenClass::PERSONAL_ACCESS_TOKEN->joseType(),
            keyId: $this->keys->activeKeyId,
            algorithm: $this->keys->algorithm,
            passphrase: $this->keys->privateKeyPassphrase(),
            clock: $this->clock,
        )->issue($claims);
    }
}
