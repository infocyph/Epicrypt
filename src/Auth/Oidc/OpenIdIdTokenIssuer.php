<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCode;
use Infocyph\Epicrypt\Auth\Token\AuthTokenClass;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\OpenIdIdTokenValidator;
use Psr\Clock\ClockInterface;

final readonly class OpenIdIdTokenIssuer
{
    public const int DEFAULT_LIFETIME_SECONDS = 300;
    public const int MAXIMUM_LIFETIME_SECONDS = 3_600;

    private OpenIdIdTokenValidator $validator;

    public function __construct(
        #[\SensitiveParameter]
        private AsymmetricSigningKeySet $keys,
        private OpenIdSubjectIdentifierProviderInterface $subjects,
        private int $lifetimeSeconds = self::DEFAULT_LIFETIME_SECONDS,
        private ClockInterface $clock = new SystemClock(),
        ?OpenIdIdTokenValidator $validator = null,
    ) {
        if ($this->keys->purpose !== KeyPurpose::OIDC_ID_TOKEN_SIGNING) {
            throw new ConfigurationException('OpenID ID-token issuer requires OIDC ID-token signing keys.');
        }
        if ($this->lifetimeSeconds < 1 || $this->lifetimeSeconds > self::MAXIMUM_LIFETIME_SECONDS) {
            throw new ConfigurationException('OpenID ID-token lifetime must be between 1 second and 1 hour.');
        }
        $this->validator = $validator ?? new OpenIdIdTokenValidator($this->clock);
    }

    public function issue(
        AuthorizationCode $authorization,
        #[\SensitiveParameter]
        ?string $accessToken = null,
        #[\SensitiveParameter]
        ?string $authorizationCode = null,
        #[\SensitiveParameter]
        ?string $state = null,
    ): OpenIdIdTokenIssue {
        if (!in_array('openid', $authorization->scopes, true)) {
            throw new ConfigurationException('OpenID ID-token issuance requires an openid authorization.');
        }
        if ($authorization->authenticationTime === null) {
            throw new ConfigurationException('OpenID ID-token issuance requires authentication time.');
        }

        $subject = $this->subjects->subject($authorization->subject, $authorization->clientId);
        AuthProtocolPolicy::assertText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OpenID subject');

        $custom = ['auth_time' => $authorization->authenticationTime];
        if ($authorization->nonce !== null) {
            $custom['nonce'] = $authorization->nonce;
        }
        if ($authorization->authenticationContext !== null) {
            $custom['acr'] = $authorization->authenticationContext;
        }
        if ($authorization->authenticationMethods !== []) {
            $custom['amr'] = $authorization->authenticationMethods;
        }
        if ($accessToken !== null) {
            $custom['at_hash'] = $this->halfHash($accessToken);
        }
        if ($authorizationCode !== null) {
            $custom['c_hash'] = $this->halfHash($authorizationCode);
        }
        if ($state !== null) {
            $custom['s_hash'] = $this->halfHash($state);
        }

        $claims = JwtClaims::issue(
            issuer: $this->keys->issuer,
            subject: $subject,
            audiences: [$authorization->clientId],
            ttlSeconds: $this->lifetimeSeconds,
            custom: $custom,
            clock: $this->clock,
        );
        $token = AsymmetricJwt::issuer(
            privateKey: $this->keys->privateKey(),
            type: AuthTokenClass::OIDC_ID_TOKEN->joseType(),
            keyId: $this->keys->activeKeyId,
            algorithm: $this->keys->algorithm,
            passphrase: $this->keys->privateKeyPassphrase(),
            clock: $this->clock,
        )->issue($claims);

        $this->validator->validate(
            claims: $claims->toArray(),
            signingAlgorithm: $this->keys->algorithm,
            clientId: $authorization->clientId,
            nonce: $authorization->nonce,
            accessToken: $accessToken,
            authorizationCode: $authorizationCode,
            state: $state,
        );

        return new OpenIdIdTokenIssue($token, $claims);
    }

    private function halfHash(#[\SensitiveParameter] string $value): string
    {
        $digest = hash($this->keys->algorithm->hashAlgorithm(), $value, true);

        return Base64Url::encode(substr($digest, 0, intdiv(strlen($digest), 2)));
    }
}
