<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Auth\Token\AuthTokenClass;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\JwtProfile;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class OAuthAccessTokenService
{
    public const int DEFAULT_LIFETIME_SECONDS = 900;

    public const int MAXIMUM_LIFETIME_SECONDS = 3600;

    private const int STORAGE_ATTEMPTS = 3;

    public function __construct(
        private AsymmetricSigningKeySet $keys,
        private OAuthAuthorizationStoreInterface $authorizations,
        private ?OAuthAccessTokenStatusStoreInterface $statusStore = null,
        private int $lifetimeSeconds = self::DEFAULT_LIFETIME_SECONDS,
        private ClockInterface $clock = new SystemClock(),
    ) {
        if ($this->keys->purpose !== KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING) {
            throw new ConfigurationException('OAuth access-token signing keys must use the OAuth access-token key purpose.');
        }
        if ($this->lifetimeSeconds < 1 || $this->lifetimeSeconds > self::MAXIMUM_LIFETIME_SECONDS) {
            throw new ConfigurationException('OAuth access-token lifetime must be between 1 and 3600 seconds.');
        }
    }

    public function immediateRevocationEnabled(): bool
    {
        return $this->statusStore !== null;
    }

    /**
     * @param array<array-key, mixed> $audiences
     * @param array<array-key, mixed> $scopes
     */
    public function issue(
        string $subject,
        string $clientId,
        array $audiences,
        array $scopes,
        ?string $authorizationId = null,
        ?string $dpopKeyThumbprint = null,
    ): OAuthAccessTokenIssue {
        AuthProtocolPolicy::assertText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth access-token subject');
        AuthProtocolPolicy::assertText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth access-token client ID');
        $audiences = AuthProtocolPolicy::normalizeAudiences($audiences, 'OAuth access-token audiences');
        $scopes = AuthProtocolPolicy::normalizeScopes($scopes, 'OAuth access-token scopes');
        if ($authorizationId !== null) {
            AuthProtocolPolicy::assertText($authorizationId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth access-token authorization ID');
        }
        if ($dpopKeyThumbprint !== null && !AuthProtocolPolicy::validSha256Base64Url($dpopKeyThumbprint)) {
            throw new ConfigurationException('OAuth access-token DPoP thumbprint must be a SHA-256 Base64URL value.');
        }

        $now = $this->clock->now()->getTimestamp();
        $ttl = $this->authorizedTtl($authorizationId, $subject, $clientId, $audiences, $scopes, $now);
        $custom = $this->customClaims($clientId, $scopes, $authorizationId, $dpopKeyThumbprint);

        $attempts = $this->statusStore === null ? 1 : self::STORAGE_ATTEMPTS;
        for ($attempt = 0; $attempt < $attempts; $attempt++) {
            $claims = JwtClaims::issue(
                issuer: $this->keys->issuer,
                subject: $subject,
                audiences: $audiences,
                ttlSeconds: $ttl,
                custom: $custom,
                clock: $this->clock,
            );
            $token = AsymmetricJwt::issuer(
                privateKey: $this->keys->privateKey(),
                type: AuthTokenClass::OAUTH_ACCESS_TOKEN->joseType(),
                keyId: $this->keys->activeKeyId,
                algorithm: $this->keys->algorithm,
                passphrase: $this->keys->privateKeyPassphrase(),
                clock: $this->clock,
            )->issue($claims);

            if ($this->statusStore === null
                || $this->statusStore->create(new OAuthAccessTokenStatusRecord(
                    issuer: $claims->issuer,
                    tokenId: $claims->jwtId,
                    subject: $claims->subject,
                    clientId: $clientId,
                    expiresAt: $claims->expiresAt,
                    authorizationId: $authorizationId,
                ))) {
                return new OAuthAccessTokenIssue($token, $claims);
            }
        }

        throw new ConfigurationException('Unable to persist a unique OAuth access-token status record.');
    }

    public function issuer(): string
    {
        return $this->keys->issuer;
    }

    public function revoke(
        #[\SensitiveParameter]
        string $token,
        string $audience,
        string $clientId,
    ): bool {
        if ($this->statusStore === null) {
            return false;
        }
        $result = $this->validate($token, $audience);
        if (!$result->cryptographicallyValid()) {
            return false;
        }
        $tokenClient = $result->claims['client_id'] ?? null;
        $tokenId = $result->claims['jti'] ?? null;
        if (!is_string($tokenClient) || !hash_equals($clientId, $tokenClient) || !is_string($tokenId)) {
            return false;
        }

        return $this->statusStore->revoke(
            $this->keys->issuer,
            $tokenId,
            $this->clock->now()->getTimestamp(),
        ) instanceof OAuthAccessTokenStatusRecord;
    }

    public function signingKeys(): AsymmetricSigningKeySet
    {
        return $this->keys;
    }

    public function validate(#[\SensitiveParameter] string $token, string $audience): OAuthAccessTokenValidationResult
    {
        AuthProtocolPolicy::assertText($audience, AuthProtocolPolicy::MAX_AUDIENCE_BYTES, 'OAuth resource audience');
        $policy = new JwtPolicy(
            expectedIssuer: $this->keys->issuer,
            expectedAudience: $audience,
            expectedType: AuthTokenClass::OAUTH_ACCESS_TOKEN->joseType(),
            maximumLifetimeSeconds: $this->lifetimeSeconds,
            profile: JwtProfile::OAUTH_ACCESS_TOKEN,
            requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id'],
            tokenClass: AuthTokenClass::OAUTH_ACCESS_TOKEN,
        );
        $jwt = AsymmetricJwt::verifier(
            publicKey: $this->keys->publicKeys(),
            policy: $policy,
            algorithm: $this->keys->algorithm,
            clock: $this->clock,
        )->verifyResult($token);
        if (!$jwt->valid) {
            return OAuthAccessTokenValidationResult::invalid($jwt->failureReason);
        }

        try {
            $state = $this->validatedState($jwt->claims);
        } catch (Throwable) {
            return OAuthAccessTokenValidationResult::inactive(
                OAuthAccessTokenValidationStatus::STATE_MISMATCH,
                $jwt->claims,
                $jwt->matchedKeyId,
            );
        }

        if ($this->statusStore !== null) {
            $record = $this->statusStore->find($this->keys->issuer, $state['token_id']);
            if (!$record instanceof OAuthAccessTokenStatusRecord
                || !$this->statusMatches($record, $state)
                || !$record->isActive($this->clock->now()->getTimestamp())) {
                return OAuthAccessTokenValidationResult::inactive(
                    OAuthAccessTokenValidationStatus::STATUS_INACTIVE,
                    $jwt->claims,
                    $jwt->matchedKeyId,
                );
            }
        }

        if ($state['authorization_id'] !== null) {
            $authorization = $this->authorizations->find($state['authorization_id']);
            if (!$authorization instanceof OAuthAuthorizationRecord
                || !$authorization->isActive($this->clock->now()->getTimestamp())
                || !$this->authorizationAllows(
                    $authorization,
                    $state['subject'],
                    $state['client_id'],
                    $state['audiences'],
                    $state['scopes'],
                )
                || $state['expires_at'] > $authorization->expiresAt) {
                return OAuthAccessTokenValidationResult::inactive(
                    OAuthAccessTokenValidationStatus::AUTHORIZATION_INACTIVE,
                    $jwt->claims,
                    $jwt->matchedKeyId,
                );
            }
        }

        return OAuthAccessTokenValidationResult::success($jwt->claims, $jwt->matchedKeyId);
    }

    /**
     * @param list<string> $audiences
     * @param list<string> $scopes
     */
    private function authorizationAllows(
        OAuthAuthorizationRecord $authorization,
        string $subject,
        string $clientId,
        array $audiences,
        array $scopes,
    ): bool {
        if (!hash_equals($authorization->subject, $subject) || !hash_equals($authorization->clientId, $clientId)) {
            return false;
        }
        foreach ($audiences as $audience) {
            if (!in_array($audience, $authorization->audiences, true)) {
                return false;
            }
        }

        return array_all($scopes, fn(string $scope): bool => in_array($scope, $authorization->scopes, true));
    }

    /**
     * @param list<string> $audiences
     * @param list<string> $scopes
     */
    private function authorizedTtl(
        ?string $authorizationId,
        string $subject,
        string $clientId,
        array $audiences,
        array $scopes,
        int $now,
    ): int {
        if ($authorizationId === null) {
            return $this->lifetimeSeconds;
        }

        $authorization = $this->authorizations->find($authorizationId);
        if (!$authorization instanceof OAuthAuthorizationRecord
            || !$authorization->isActive($now)
            || !$this->authorizationAllows($authorization, $subject, $clientId, $audiences, $scopes)) {
            throw new ConfigurationException('OAuth authorization is not active for the requested access token.');
        }

        $ttl = min($this->lifetimeSeconds, $authorization->expiresAt - $now);
        if ($ttl < 1) {
            throw new ConfigurationException('OAuth authorization expires before an access token can be issued.');
        }

        return $ttl;
    }

    /**
     * @param list<string> $scopes
     * @return array<string, mixed>
     */
    private function customClaims(
        string $clientId,
        array $scopes,
        ?string $authorizationId,
        ?string $dpopKeyThumbprint,
    ): array {
        $custom = ['client_id' => $clientId];
        if ($scopes !== []) {
            $custom['scope'] = $scopes;
        }
        if ($authorizationId !== null) {
            $custom['authorization_id'] = $authorizationId;
        }
        if ($dpopKeyThumbprint !== null) {
            $custom['cnf'] = ['jkt' => $dpopKeyThumbprint];
        }

        return $custom;
    }

    /** @param array{token_id:string,subject:string,client_id:string,expires_at:int,authorization_id:?string} $state */
    private function statusMatches(OAuthAccessTokenStatusRecord $record, array $state): bool
    {
        return hash_equals($record->issuer, $this->keys->issuer)
            && hash_equals($record->tokenId, $state['token_id'])
            && hash_equals($record->subject, $state['subject'])
            && hash_equals($record->clientId, $state['client_id'])
            && $record->expiresAt === $state['expires_at']
            && $record->authorizationId === $state['authorization_id'];
    }

    /**
     * @param array<string, mixed> $claims
     * @return array{token_id:string,subject:string,client_id:string,audiences:list<string>,scopes:list<string>,expires_at:int,authorization_id:?string,dpop_jkt:?string}
     */
    private function validatedState(array $claims): array
    {
        $tokenId = $claims['jti'] ?? null;
        $subject = $claims['sub'] ?? null;
        $clientId = $claims['client_id'] ?? null;
        $expiresAt = $claims['exp'] ?? null;
        if (!is_string($tokenId) || !is_string($subject) || !is_string($clientId) || !is_int($expiresAt)) {
            throw new ConfigurationException('OAuth access-token state claims are invalid.');
        }
        AuthProtocolPolicy::assertText($tokenId, 128, 'OAuth access-token ID');
        AuthProtocolPolicy::assertText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth access-token subject');
        AuthProtocolPolicy::assertText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth access-token client ID');

        $audienceClaim = $claims['aud'] ?? null;
        $audiences = is_string($audienceClaim) ? [$audienceClaim] : $audienceClaim;
        if (!is_array($audiences)) {
            throw new ConfigurationException('OAuth access-token audiences are invalid.');
        }
        $audiences = AuthProtocolPolicy::normalizeAudiences($audiences, 'OAuth access-token audiences');

        $scopeClaim = $claims['scope'] ?? '';
        if (!is_string($scopeClaim)) {
            throw new ConfigurationException('OAuth access-token scope is invalid.');
        }
        $scopes = $scopeClaim === '' ? [] : AuthProtocolPolicy::normalizeScopes(explode(' ', $scopeClaim), 'OAuth access-token scopes');

        $authorizationId = $claims['authorization_id'] ?? null;
        if ($authorizationId !== null) {
            if (!is_string($authorizationId)) {
                throw new ConfigurationException('OAuth access-token authorization ID is invalid.');
            }
            AuthProtocolPolicy::assertText($authorizationId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth access-token authorization ID');
        }

        $dpopJkt = null;
        if (array_key_exists('cnf', $claims)) {
            $cnf = $claims['cnf'];
            if (!is_array($cnf)
                || array_keys($cnf) !== ['jkt']
                || !is_string($cnf['jkt'])
                || !AuthProtocolPolicy::validSha256Base64Url($cnf['jkt'])) {
                throw new ConfigurationException('OAuth access-token cnf claim is invalid.');
            }
            $dpopJkt = $cnf['jkt'];
        }

        return [
            'token_id' => $tokenId,
            'subject' => $subject,
            'client_id' => $clientId,
            'audiences' => $audiences,
            'scopes' => $scopes,
            'expires_at' => $expiresAt,
            'authorization_id' => $authorizationId,
            'dpop_jkt' => $dpopJkt,
        ];
    }
}
