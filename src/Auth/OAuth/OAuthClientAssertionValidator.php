<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jws;
use Infocyph\Epicrypt\Token\Jwt\JwtReplayStoreInterface;
use Infocyph\Epicrypt\Token\Jwt\Support\JosePolicy;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class OAuthClientAssertionValidator
{
    public const int DEFAULT_LEEWAY_SECONDS = 30;

    public const int DEFAULT_MAXIMUM_FUTURE_IAT_SECONDS = 30;

    public const int DEFAULT_MAXIMUM_LIFETIME_SECONDS = 300;

    private const int MAX_JTI_BYTES = 128;

    private const string REPLAY_NAMESPACE_PREFIX = 'oauth.client-assertion:';

    public function __construct(
        private JwtReplayStoreInterface $replayStore,
        private ClockInterface $clock = new SystemClock(),
        private int $maximumLifetimeSeconds = self::DEFAULT_MAXIMUM_LIFETIME_SECONDS,
        private int $leewaySeconds = self::DEFAULT_LEEWAY_SECONDS,
        private int $maximumFutureIssuedAtSeconds = self::DEFAULT_MAXIMUM_FUTURE_IAT_SECONDS,
    ) {
        if ($this->maximumLifetimeSeconds < 1 || $this->maximumLifetimeSeconds > 3_600
            || $this->leewaySeconds < 0 || $this->leewaySeconds > 300
            || $this->maximumFutureIssuedAtSeconds < 0 || $this->maximumFutureIssuedAtSeconds > 300) {
            throw new ConfigurationException('OAuth client-assertion temporal policy is outside supported bounds.');
        }
    }

    public function validate(
        OAuthClient $client,
        #[\SensitiveParameter]
        string $assertion,
        string $audience,
    ): OAuthClientAssertionResult {
        if (!$client->allowsAuthenticationMethod(OAuthClientAuthenticationMethod::PRIVATE_KEY_JWT)
            || !$client->assertionKeys instanceof OAuthClientKeySet) {
            throw new ConfigurationException('OAuth client is not configured for private_key_jwt authentication.');
        }
        if (!AuthProtocolPolicy::validText($audience, AuthProtocolPolicy::MAX_AUDIENCE_BYTES)) {
            throw new ConfigurationException('OAuth client-assertion audience policy is invalid.');
        }

        try {
            [, , , $header, $claims] = JwtToken::parse($assertion);
        } catch (Throwable) {
            return OAuthClientAssertionResult::failure(OAuthClientAssertionStatus::MALFORMED);
        }

        $headerProfile = $this->headerProfile($header);
        if ($headerProfile === null) {
            return OAuthClientAssertionResult::failure(OAuthClientAssertionStatus::INVALID_HEADER);
        }
        [$algorithm, $keyId] = $headerProfile;

        $claimStatus = $this->validateClaims($claims, $client->clientId, $audience);
        if ($claimStatus !== OAuthClientAssertionStatus::VALID) {
            return OAuthClientAssertionResult::failure($claimStatus);
        }

        try {
            $publicKey = $client->assertionKeys->resolvePublicKey($keyId, $algorithm);
            $validSignature = Jws::verifier($publicKey, $algorithm, $keyId)->verifyCompact($assertion);
        } catch (Throwable) {
            $validSignature = false;
        }
        if (!$validSignature) {
            return OAuthClientAssertionResult::failure(OAuthClientAssertionStatus::INVALID_SIGNATURE);
        }

        $tokenId = $claims['jti'];
        $expiresAt = $claims['exp'];
        if (!is_string($tokenId) || !is_int($expiresAt)) {
            return OAuthClientAssertionResult::failure(OAuthClientAssertionStatus::INVALID_CLAIMS);
        }
        $namespace = self::REPLAY_NAMESPACE_PREFIX . hash('sha256', $client->clientId);
        if (!$this->replayStore->consume($namespace, $tokenId, $expiresAt + $this->leewaySeconds)) {
            return OAuthClientAssertionResult::failure(OAuthClientAssertionStatus::REPLAYED);
        }

        return OAuthClientAssertionResult::success($claims);
    }

    private function audienceMatches(mixed $claim, string $expected): bool
    {
        if (is_string($claim)) {
            return AuthProtocolPolicy::validText($claim, AuthProtocolPolicy::MAX_AUDIENCE_BYTES)
                && hash_equals($expected, $claim);
        }
        if (!is_array($claim)
            || $claim === []
            || !array_is_list($claim)
            || count($claim) > AuthProtocolPolicy::MAX_AUDIENCE_COUNT) {
            return false;
        }

        $matched = false;
        foreach ($claim as $audience) {
            if (!is_string($audience)
                || !AuthProtocolPolicy::validText($audience, AuthProtocolPolicy::MAX_AUDIENCE_BYTES)) {
                return false;
            }
            $matched = $matched || hash_equals($expected, $audience);
        }

        return $matched;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function hasRequiredClaims(array $claims): bool
    {
        return array_all(
            ['iss', 'sub', 'aud', 'exp', 'iat', 'jti'],
            static fn (string $required): bool => array_key_exists($required, $claims),
        );
    }

    /**
     * @param array<string, mixed> $header
     * @return null|array{AsymmetricJwtAlgorithm, ?string}
     */
    private function headerProfile(array $header): ?array
    {
        if (array_diff_key($header, ['alg' => true, 'kid' => true, 'typ' => true]) !== []) {
            return null;
        }
        $algorithmValue = $header['alg'] ?? null;
        if (!is_string($algorithmValue)) {
            return null;
        }
        $algorithm = AsymmetricJwtAlgorithm::tryFrom($algorithmValue);
        if (!$algorithm instanceof AsymmetricJwtAlgorithm) {
            return null;
        }
        $keyId = $header['kid'] ?? null;
        if ($keyId !== null && (!is_string($keyId) || !JosePolicy::isKeyId($keyId))) {
            return null;
        }
        if (array_key_exists('typ', $header) && $header['typ'] !== 'JWT') {
            return null;
        }

        return [$algorithm, $keyId];
    }

    /** @param array<string, mixed> $claims */
    private function validateClaims(array $claims, string $clientId, string $audience): OAuthClientAssertionStatus
    {
        if (count($claims) > AuthProtocolPolicy::MAX_AUTH_CLAIMS || !$this->hasRequiredClaims($claims)) {
            return OAuthClientAssertionStatus::INVALID_CLAIMS;
        }
        if (!is_string($claims['iss'])
            || !is_string($claims['sub'])
            || !hash_equals($clientId, $claims['iss'])
            || !hash_equals($clientId, $claims['sub'])
            || !is_int($claims['exp'])
            || !is_int($claims['iat'])
            || !is_string($claims['jti'])
            || !AuthProtocolPolicy::validText($claims['jti'], self::MAX_JTI_BYTES)
            || !$this->audienceMatches($claims['aud'], $audience)) {
            return OAuthClientAssertionStatus::INVALID_CLAIMS;
        }
        if (array_key_exists('nbf', $claims) && !is_int($claims['nbf'])) {
            return OAuthClientAssertionStatus::INVALID_CLAIMS;
        }

        $issuedAt = $claims['iat'];
        $expiresAt = $claims['exp'];
        $notBefore = $claims['nbf'] ?? null;
        if ($issuedAt < 1
            || $expiresAt <= $issuedAt
            || ($expiresAt - $issuedAt) > $this->maximumLifetimeSeconds
            || (is_int($notBefore) && $notBefore >= $expiresAt)) {
            return OAuthClientAssertionStatus::INVALID_CLAIMS;
        }

        $now = $this->clock->now()->getTimestamp();
        if ($issuedAt > ($now + $this->maximumFutureIssuedAtSeconds)) {
            return OAuthClientAssertionStatus::NOT_YET_VALID;
        }
        if (is_int($notBefore) && $now < ($notBefore - $this->leewaySeconds)) {
            return OAuthClientAssertionStatus::NOT_YET_VALID;
        }
        if ($now >= ($expiresAt + $this->leewaySeconds)) {
            return OAuthClientAssertionStatus::EXPIRED;
        }

        return OAuthClientAssertionStatus::VALID;
    }
}
