<?php

declare(strict_types=1);

it('redacts secret-bearing parameters throughout production call chains', function () {
    $classMap = require dirname(__DIR__, 2).'/vendor/composer/autoload_classmap.php';
    $sensitiveName = '/(?:password|passphrase|secret|plaintext|privatekey|keypair|token|proof|signedurl|serialized|pkcs12|keyring|keyset|keycandidates|inputkeymaterial|rootkey|sharedcek|^cek$|hash|digest)/i';

    $nonSecretParameters = array_fill_keys([
        'Infocyph\\Epicrypt\\Certificate\\CertificateOptions::__construct::$digestAlgorithm',
        'Infocyph\\Epicrypt\\Certificate\\KeyPairGenerator::__construct::$supportsPassphrase',
        'Infocyph\\Epicrypt\\Certificate\\OpenSSL\\CertificateBuilder::__construct::$digestAlgorithm',
        'Infocyph\\Epicrypt\\Certificate\\Sodium\\Support\\SodiumKeyPairFactory::generate::$createKeyPair',
        'Infocyph\\Epicrypt\\Crypto\\Ristretto255::fromHash::$uniformHash',
        'Infocyph\\Epicrypt\\Crypto\\Signature::verify::$key',
        'Infocyph\\Epicrypt\\Crypto\\Signature::verifyWithBinaryKey::$key',
        'Infocyph\\Epicrypt\\Integrity\\FileHasher::digestIsWellFormed::$digest',
        'Infocyph\\Epicrypt\\Integrity\\FileHasher::verify::$digest',
        'Infocyph\\Epicrypt\\Integrity\\StringHasher::isWellFormedDigest::$digest',
        'Infocyph\\Epicrypt\\Integrity\\StringHasher::verify::$digest',
        'Infocyph\\Epicrypt\\Password\\PasswordVerificationResult::__construct::$needsRehash',
        'Infocyph\\Epicrypt\\Token\\Jwt\\AsymmetricJwt::rsaPssPublicKey::$key',
        'Infocyph\\Epicrypt\\Token\\Jwt\\DpopProof::validateAccessTokenBinding::$accessTokenClaims',
        'Infocyph\\Epicrypt\\Token\\Jwt\\JwtReplayStoreInterface::consume::$tokenId',
        'Infocyph\\Epicrypt\\Token\\Jwt\\JwtReplayStoreInterface::isRevoked::$tokenId',
        'Infocyph\\Epicrypt\\Token\\Jwt\\Support\\JwkCertificateBinding::validateThumbprint::$hash',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\AuthorizationCode::__construct::$redirectUriHash',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\AuthorizationCodeRecord::__construct::$stateDigest',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthAccessTokenInspector::__construct::$tokens',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthAccessTokenStatusRecord::__construct::$tokenId',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthAccessTokenStatusStoreInterface::find::$tokenId',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthAccessTokenStatusStoreInterface::revoke::$tokenId',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthAuthorizationServerMetadata::__construct::$tokenEndpoint',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthClientSecret::hash::$hasher',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthDpopValidator::__construct::$proof',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthDpopValidator::validateTokenEndpoint::$tokenEndpointUri',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthDpopValidator::validateResourceRequest::$accessTokenClaims',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthIntrospectionEndpoint::__construct::$accessTokens',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthIntrospectionEndpoint::__construct::$refreshTokens',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthResourceAccessTokenResult::__construct::$accessToken',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthResourceAccessTokenResult::failure::$accessToken',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthResourceAccessTokenResult::success::$accessToken',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthResourceAccessTokenValidator::__construct::$accessTokens',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthRevocationEndpoint::__construct::$accessTokens',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthRevocationEndpoint::__construct::$refreshTokens',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthTokenEndpoint::__construct::$accessTokens',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthTokenEndpoint::__construct::$refreshTokens',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthTokenEndpoint::__construct::$tokenEndpointUri',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\OAuthTokenResponse::__construct::$tokenType',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\RefreshTokenArtifactClaims::__construct::$tokenId',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\RefreshTokenRecord::__construct::$tokenId',
        'Infocyph\\Epicrypt\\Auth\\OAuth\\RefreshTokenStoreInterface::revokeFamily::$tokenId',
        'Infocyph\\Epicrypt\\Auth\\Personal\\PersonalAccessTokenRecord::__construct::$tokenId',
        'Infocyph\\Epicrypt\\Auth\\Personal\\PersonalAccessTokenStoreInterface::find::$tokenId',
        'Infocyph\\Epicrypt\\Auth\\Personal\\PersonalAccessTokenStoreInterface::revoke::$tokenId',
        'Infocyph\\Epicrypt\\Token\\Jwt\\JwtPolicy::__construct::$tokenClass',
        'Infocyph\\Epicrypt\\Token\\Jwt\\JwtPolicy::validateProfile::$tokenClass',
    ], true);

    $missing = [];
    foreach ($classMap as $class => $file) {
        if (!str_starts_with($class, 'Infocyph\\Epicrypt') || !str_contains($file, '/src/')) {
            continue;
        }

        $reflection = new ReflectionClass($class);
        foreach ($reflection->getMethods() as $method) {
            if ($method->getDeclaringClass()->getName() !== $class) {
                continue;
            }

            foreach ($method->getParameters() as $parameter) {
                $identifier = sprintf('%s::%s::%s', $class, $method->getName(), '$'.$parameter->getName());
                $isSecretBearing = preg_match($sensitiveName, $parameter->getName()) === 1
                    || $parameter->getName() === 'key';
                if (!$isSecretBearing || isset($nonSecretParameters[$identifier])) {
                    continue;
                }

                if ($parameter->getAttributes(SensitiveParameter::class) === []) {
                    $missing[] = $identifier;
                }
            }
        }
    }

    expect($missing)->toBe([]);
});
