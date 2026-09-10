<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenArtifact;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenGrant;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenManager;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenRotationStatus;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Tests\Support\InMemoryRefreshTokenStore;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;

it('executes the documented OAuth access and refresh token lifecycle', function () {
    $issuerUrl = 'https://auth.example.com';
    $signingKeys = KeyPairGenerator::ec()->generate();
    $issuer = AsymmetricJwt::issuer($signingKeys['private'], 'at+jwt', 'oauth-signing-2026-08');
    $verifier = AsymmetricJwt::verifier($signingKeys['public'], JwtPolicy::oauthAccessToken($issuerUrl, 'orders-api'));
    $refreshArtifact = new RefreshTokenArtifact(
        new KeyRing([
            new KeyRingEntry(
                'oauth-refresh-2026-09', random_bytes(32), KeyStatus::ACTIVE,
                KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION, JweKeyManagementAlgorithm::DIRECT->value,
                issuer: $issuerUrl,
            ),
        ]),
        $issuerUrl,
    );
    $refreshTokens = new RefreshTokenManager(new InMemoryRefreshTokenStore(), $refreshArtifact);

    $issueAccessToken = static function (RefreshTokenGrant $grant) use ($issuer, $issuerUrl): string {
        $custom = ['client_id' => $grant->clientId];
        if ($grant->scopes !== []) {
            $custom['scope'] = implode(' ', $grant->scopes);
        }
        if ($grant->dpopKeyThumbprint !== null) {
            $custom['cnf'] = ['jkt' => $grant->dpopKeyThumbprint];
        }
        return $issuer->issue(JwtClaims::issue($issuerUrl, $grant->subject, $grant->audiences, 300, $custom));
    };

    $thumbprint = str_repeat('A', 43);
    $grant = new RefreshTokenGrant('authorization-grant-42', 'user-42', 'browser-client', ['orders-api'], ['orders:read', 'orders:write'], time() + 90 * 86400, $thumbprint);
    $accessToken = $issueAccessToken($grant);
    $refreshToken = $refreshTokens->issue($grant);
    $verified = $verifier->verifyResult($accessToken);
    expect($verified->valid)->toBeTrue()
        ->and($verified->claims['scope'])->toBe('orders:read orders:write')
        ->and($verified->claims['cnf'])->toBe(['jkt' => $thumbprint]);

    $rotation = $refreshTokens->rotate($refreshToken, 'browser-client', $thumbprint, requestedScopes: ['orders:read']);
    expect($rotation->rotated)->toBeTrue()->and($rotation->grant?->scopes)->toBe(['orders:read'])->and($rotation->token)->not->toBeNull();
    if (!$rotation->grant instanceof RefreshTokenGrant || !is_string($rotation->token)) {
        throw new RuntimeException('Documented refresh-token rotation did not return its successor.');
    }
    $replacement = $issueAccessToken($rotation->grant);
    expect($verifier->verifyResult($replacement)->claims['scope'])->toBe('orders:read');
    expect($refreshTokens->rotate($refreshToken, 'browser-client', $thumbprint)->status)->toBe(RefreshTokenRotationStatus::REUSED)
        ->and($refreshTokens->rotate($rotation->token, 'browser-client', $thumbprint)->status)->toBe(RefreshTokenRotationStatus::REVOKED);
});
