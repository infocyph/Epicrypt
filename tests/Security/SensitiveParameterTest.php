<?php

declare(strict_types=1);

it('redacts secret-bearing parameters throughout production call chains', function () {
    $classMap = require dirname(__DIR__, 2).'/vendor/composer/autoload_classmap.php';
    $sensitiveName = '/(?:password|passphrase|secret|plaintext|privatekey|keypair|token|proof|signedurl|serialized|pkcs12|keyring|keyset|keycandidates|inputkeymaterial|rootkey|sharedcek|^cek$|hash|digest)/i';

    $nonSecretParameters = array_fill_keys([
        'Infocyph\Epicrypt\Certificate\CertificateOptions::__construct::$digestAlgorithm',
        'Infocyph\Epicrypt\Certificate\KeyPairGenerator::__construct::$supportsPassphrase',
        'Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder::__construct::$digestAlgorithm',
        'Infocyph\Epicrypt\Certificate\Sodium\Support\SodiumKeyPairFactory::generate::$createKeyPair',
        'Infocyph\Epicrypt\Crypto\Ristretto255::fromHash::$uniformHash',
        'Infocyph\Epicrypt\Crypto\Signature::verify::$key',
        'Infocyph\Epicrypt\Crypto\Signature::verifyWithBinaryKey::$key',
        'Infocyph\Epicrypt\Integrity\FileHasher::verify::$digest',
        'Infocyph\Epicrypt\Integrity\StringHasher::isWellFormedDigest::$digest',
        'Infocyph\Epicrypt\Integrity\StringHasher::verify::$digest',
        'Infocyph\Epicrypt\Password\PasswordVerificationResult::__construct::$needsRehash',
        'Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt::rsaPssPublicKey::$key',
        'Infocyph\Epicrypt\Token\Jwt\DpopProof::validateAccessTokenBinding::$accessTokenClaims',
        'Infocyph\Epicrypt\Token\Jwt\JwtReplayStoreInterface::consume::$tokenId',
        'Infocyph\Epicrypt\Token\Jwt\JwtReplayStoreInterface::isRevoked::$tokenId',
        'Infocyph\Epicrypt\Token\Jwt\Support\JwkCertificateBinding::validateThumbprint::$hash',
        'Infocyph\Epicrypt\Token\Opaque\RefreshTokenManager::__construct::$tokens',
    ], true);

    $missing = [];
    foreach ($classMap as $class => $file) {
        if (!str_starts_with($class, 'Infocyph\Epicrypt') || !str_contains($file, '/src/')) {
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
