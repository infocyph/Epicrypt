<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\Token\AuthTokenClass;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtFailureReason;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\JwtProfile;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;

it('assigns independent key domains to authentication credential classes', function () {
    expect(AuthTokenClass::OAUTH_ACCESS_TOKEN->keyDomain())->toBe('oauth.access-token.signing.v1')
        ->and(AuthTokenClass::OAUTH_ACCESS_TOKEN->keyPurpose())->toBe(KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING)
        ->and(AuthTokenClass::OAUTH_AUTHORIZATION_CODE->keyDomain())->toBe('oauth.authorization-code.protection.v1')
        ->and(AuthTokenClass::OAUTH_AUTHORIZATION_CODE->keyPurpose())->toBe(KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION)
        ->and(AuthTokenClass::OAUTH_REFRESH_TOKEN->keyDomain())->toBe('oauth.refresh-token.protection.v1')
        ->and(AuthTokenClass::OAUTH_REFRESH_TOKEN->keyPurpose())->toBe(KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION)
        ->and(AuthTokenClass::OIDC_ID_TOKEN->keyDomain())->toBe('oidc.id-token.signing.v1')
        ->and(AuthTokenClass::OIDC_ID_TOKEN->keyPurpose())->toBe(KeyPurpose::OIDC_ID_TOKEN_SIGNING)
        ->and(AuthTokenClass::PERSONAL_ACCESS_TOKEN->keyDomain())->toBe('api.personal-token.signing.v1')
        ->and(AuthTokenClass::PERSONAL_ACCESS_TOKEN->keyPurpose())->toBe(KeyPurpose::API_PERSONAL_TOKEN_SIGNING)
        ->and(AuthTokenClass::DPOP_PROOF->keyPurpose())->toBeNull()
        ->and(AuthTokenClass::OAUTH_CLIENT_ASSERTION->keyPurpose())->toBeNull();
});

it('binds OAuth and OIDC JWT policies to their signing key purposes', function () {
    expect(JwtPolicy::oauthAccessToken('issuer', 'api')->keyPurpose)
        ->toBe(KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING)
        ->and(JwtPolicy::openIdIdToken('issuer', 'client')->keyPurpose)
        ->toBe(KeyPurpose::OIDC_ID_TOKEN_SIGNING)
        ->and(JwtPolicy::generic('issuer', 'api')->keyPurpose)
        ->toBe(KeyPurpose::JWT_SIGNING);
});

it('rejects a key-purpose mismatch in authentication JWT policy configuration', function () {
    expect(fn () => new JwtPolicy(
        'issuer',
        'api',
        'at+jwt',
        profile: JwtProfile::OAUTH_ACCESS_TOKEN,
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id'],
        tokenClass: AuthTokenClass::OAUTH_ACCESS_TOKEN,
        keyPurpose: KeyPurpose::API_PERSONAL_TOKEN_SIGNING,
    ))->toThrow(ConfigurationException::class);
});

it('isolates symmetric OAuth access-token verification by key purpose', function () {
    $key = random_bytes(64);
    $claims = JwtClaims::issue('issuer', 'subject', ['api'], 300, [
        'client_id' => 'client-1',
        'scope' => 'orders:read',
    ]);
    $token = SymmetricJwt::issuer(
        $key,
        AuthTokenClass::OAUTH_ACCESS_TOKEN->joseType(),
        'oauth-key',
    )->issue($claims);
    $policy = JwtPolicy::oauthAccessToken('issuer', 'api');

    $wrongPurpose = new KeyRing([
        new KeyRingEntry(
            'oauth-key',
            $key,
            KeyStatus::ACTIVE,
            KeyPurpose::JWT_SIGNING,
            SymmetricJwtAlgorithm::HS512->value,
            issuer: 'issuer',
        ),
    ]);
    expect(SymmetricJwt::verifier($wrongPurpose, $policy)->verifyResult($token)->failureReason)
        ->toBe(JwtFailureReason::UNKNOWN_KEY);

    $correctPurpose = new KeyRing([
        new KeyRingEntry(
            'oauth-key',
            $key,
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING,
            SymmetricJwtAlgorithm::HS512->value,
            issuer: 'issuer',
        ),
    ]);
    expect(SymmetricJwt::verifier($correctPurpose, $policy)->verify($token))->toBeTrue();
});

it('isolates asymmetric OAuth access-token verification by key purpose', function () {
    $pair = KeyPairGenerator::ec()->generate();
    $claims = JwtClaims::issue('issuer', 'subject', ['api'], 300, [
        'client_id' => 'client-1',
        'scope' => 'orders:read',
    ]);
    $token = AsymmetricJwt::issuer(
        $pair['private'],
        AuthTokenClass::OAUTH_ACCESS_TOKEN->joseType(),
        'oauth-key',
        AsymmetricJwtAlgorithm::ES256,
    )->issue($claims);
    $policy = JwtPolicy::oauthAccessToken('issuer', 'api');

    $wrongPurpose = new KeyRing([
        new KeyRingEntry(
            'oauth-key',
            $pair['public'],
            KeyStatus::ACTIVE,
            KeyPurpose::OIDC_ID_TOKEN_SIGNING,
            AsymmetricJwtAlgorithm::ES256->value,
            issuer: 'issuer',
        ),
    ]);
    expect(AsymmetricJwt::verifier($wrongPurpose, $policy)->verifyResult($token)->failureReason)
        ->toBe(JwtFailureReason::UNKNOWN_KEY);

    $correctPurpose = new KeyRing([
        new KeyRingEntry(
            'oauth-key',
            $pair['public'],
            KeyStatus::ACTIVE,
            KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING,
            AsymmetricJwtAlgorithm::ES256->value,
            issuer: 'issuer',
        ),
    ]);
    expect(AsymmetricJwt::verifier($correctPurpose, $policy)->verify($token))->toBeTrue();
});
