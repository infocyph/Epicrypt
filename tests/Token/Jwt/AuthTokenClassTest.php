<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\Token\AuthTokenClass;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtFailureReason;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\JwtProfile;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;

it('defines stable authentication token classes and JOSE media types', function () {
    expect(AuthTokenClass::OAUTH_ACCESS_TOKEN->value)->toBe('oauth.access-token')
        ->and(AuthTokenClass::OAUTH_ACCESS_TOKEN->joseType())->toBe('at+jwt')
        ->and(AuthTokenClass::OAUTH_ACCESS_TOKEN->mediaType())->toBe('application/at+jwt')
        ->and(AuthTokenClass::OAUTH_AUTHORIZATION_CODE->joseType())->toBe('oauth-authz-code+jwt')
        ->and(AuthTokenClass::OAUTH_AUTHORIZATION_CODE->requiresConfidentiality())->toBeTrue()
        ->and(AuthTokenClass::OAUTH_REFRESH_TOKEN->requiresConfidentiality())->toBeTrue()
        ->and(AuthTokenClass::OIDC_ID_TOKEN->joseType())->toBe('JWT')
        ->and(AuthTokenClass::OIDC_ID_TOKEN->mediaType())->toBe('application/jwt')
        ->and(AuthTokenClass::DPOP_PROOF->joseType())->toBe('dpop+jwt')
        ->and(AuthTokenClass::PERSONAL_ACCESS_TOKEN->joseType())->toBe('pat+jwt')
        ->and(AuthTokenClass::PERSONAL_ACCESS_TOKEN->requiresConfidentiality())->toBeFalse();
});

it('normalizes equivalent JOSE type forms without crossing token classes', function () {
    expect(AuthTokenClass::OAUTH_ACCESS_TOKEN->acceptsJoseType('at+jwt'))->toBeTrue()
        ->and(AuthTokenClass::OAUTH_ACCESS_TOKEN->acceptsJoseType('application/at+jwt'))->toBeTrue()
        ->and(AuthTokenClass::OAUTH_ACCESS_TOKEN->acceptsJoseType('AT+JWT'))->toBeTrue()
        ->and(AuthTokenClass::OAUTH_ACCESS_TOKEN->acceptsJoseType('pat+jwt'))->toBeFalse()
        ->and(AuthTokenClass::PERSONAL_ACCESS_TOKEN->acceptsJoseType('application/pat+jwt'))->toBeTrue()
        ->and(AuthTokenClass::OIDC_ID_TOKEN->acceptsJoseType('application/jwt'))->toBeTrue()
        ->and(AuthTokenClass::DPOP_PROOF->acceptsJoseType('at+jwt'))->toBeFalse();
});

it('binds existing OAuth and OIDC policies to explicit authentication token classes', function () {
    $oauth = JwtPolicy::oauthAccessToken('https://issuer.example', 'orders-api');
    $oidc = JwtPolicy::openIdIdToken('https://issuer.example', 'client-1');

    expect($oauth->tokenClass)->toBe(AuthTokenClass::OAUTH_ACCESS_TOKEN)
        ->and($oauth->acceptsType('application/at+jwt'))->toBeTrue()
        ->and($oauth->acceptsType('pat+jwt'))->toBeFalse()
        ->and($oidc->tokenClass)->toBe(AuthTokenClass::OIDC_ID_TOKEN)
        ->and($oidc->acceptsType('JWT'))->toBeTrue()
        ->and($oidc->acceptsType('application/jwt'))->toBeTrue()
        ->and($oidc->acceptsType('at+jwt'))->toBeFalse();
});

it('rejects token-class substitution before claims are accepted', function () {
    $key = random_bytes(64);
    $claims = JwtClaims::issue(
        'https://issuer.example',
        'user-7',
        ['orders-api'],
        300,
        ['client_id' => 'client-1', 'scope' => 'orders:read'],
    );
    $patShapedToken = SymmetricJwt::issuer($key, AuthTokenClass::PERSONAL_ACCESS_TOKEN->joseType())->issue($claims);
    $result = SymmetricJwt::verifier(
        $key,
        JwtPolicy::oauthAccessToken('https://issuer.example', 'orders-api'),
    )->verifyResult($patShapedToken);

    expect($result->valid)->toBeFalse()
        ->and($result->failureReason)->toBe(JwtFailureReason::INVALID_TYPE);
});

it('rejects inconsistent authentication token class policy configuration', function () {
    expect(fn () => new JwtPolicy(
        'issuer',
        'api',
        'at+jwt',
        profile: JwtProfile::OAUTH_ACCESS_TOKEN,
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id'],
    ))->toThrow(ConfigurationException::class)
        ->and(fn () => new JwtPolicy(
            'issuer',
            'api',
            'at+jwt',
            profile: JwtProfile::OAUTH_ACCESS_TOKEN,
            requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id'],
            tokenClass: AuthTokenClass::PERSONAL_ACCESS_TOKEN,
        ))->toThrow(ConfigurationException::class)
        ->and(fn () => new JwtPolicy(
            'issuer',
            'client',
            'JWT',
            profile: JwtProfile::OPENID_ID_TOKEN,
            requiredClaims: ['iss', 'aud', 'exp', 'iat'],
        ))->toThrow(ConfigurationException::class);
});
