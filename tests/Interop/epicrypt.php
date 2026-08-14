<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwe;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\Jws;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

const INTEROP_PAYLOAD = 'Epicrypt JOSE interoperability payload v1';

/** @param array<string, mixed> $document */
function writeDocument(string $path, array $document): void
{
    $json = json_encode($document, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    if (file_put_contents($path, $json . "\n") === false || !chmod($path, 0600)) {
        throw new RuntimeException('Unable to write interoperability document.');
    }
}

/** @return array<string, mixed> */
function readDocument(string $path): array
{
    $json = file_get_contents($path);
    if ($json === false) {
        throw new RuntimeException('Unable to read interoperability document.');
    }
    $document = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($document)) {
        throw new RuntimeException('Interoperability document must be an object.');
    }

    return $document;
}

/** @return array{private: string, public: string} */
function generateEcPair(OpenSslCurveName $curve): array
{
    return KeyPairGenerator::ec($curve)->generate();
}

/** @return array<string, mixed> */
function produceFixtures(): array
{
    $jwks = new Jwks();
    $rsa = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $ec = [
        'ES256' => generateEcPair(OpenSslCurveName::PRIME256V1),
        'ES384' => generateEcPair(OpenSslCurveName::SECP384R1),
        'ES512' => generateEcPair(OpenSslCurveName::SECP521R1),
    ];
    $ed = KeyPairGenerator::sodiumSign()->generate();
    $x25519 = KeyPairGenerator::sodium()->generate();
    $hmac = [
        'HS256' => random_bytes(32),
        'HS384' => random_bytes(48),
        'HS512' => random_bytes(64),
    ];
    $symmetricJwe = [
        'dir' => random_bytes(32),
        'A256KW' => random_bytes(32),
        'A256GCMKW' => random_bytes(32),
    ];

    $jws = [];
    foreach (SymmetricJwtAlgorithm::cases() as $algorithm) {
        $signer = Jws::signer($hmac[$algorithm->value], $algorithm, 'interop-' . strtolower($algorithm->value));
        $jws[$algorithm->value] = [
            'compact' => $signer->signCompact(INTEROP_PAYLOAD),
            'flattened' => $signer->signFlattened(INTEROP_PAYLOAD),
        ];
    }
    foreach (AsymmetricJwtAlgorithm::cases() as $algorithm) {
        $key = match (true) {
            $algorithm->isEdDsa() => $ed['private'],
            str_starts_with($algorithm->value, 'ES') => $ec[$algorithm->value]['private'],
            default => $rsa['private'],
        };
        $signer = Jws::signer($key, $algorithm, 'interop-' . strtolower($algorithm->value));
        $jws[$algorithm->value] = [
            'compact' => $signer->signCompact(INTEROP_PAYLOAD),
            'flattened' => $signer->signFlattened(INTEROP_PAYLOAD),
        ];
    }

    $psSigner = Jws::signer($rsa['private'], AsymmetricJwtAlgorithm::PS256, 'interop-ps256');
    $edSigner = Jws::signer($ed['private'], AsymmetricJwtAlgorithm::EDDSA, 'interop-eddsa');
    $detachedSigner = Jws::signer($hmac['HS256'], SymmetricJwtAlgorithm::HS256, 'interop-rfc7797');

    $jwe = [];
    foreach (JweKeyManagementAlgorithm::cases() as $algorithm) {
        $key = match ($algorithm) {
            JweKeyManagementAlgorithm::DIRECT,
            JweKeyManagementAlgorithm::A256KW,
            JweKeyManagementAlgorithm::A256GCMKW => $symmetricJwe[$algorithm->value],
            JweKeyManagementAlgorithm::RSA_OAEP_256 => $rsa['public'],
            JweKeyManagementAlgorithm::ECDH_ES,
            JweKeyManagementAlgorithm::ECDH_ES_A256KW => $x25519['public'],
        };
        $service = new Jwe($key, $algorithm, keyId: 'interop-jwe');
        $jwe[$algorithm->value] = [
            'compact' => $service->encryptCompact(INTEROP_PAYLOAD),
            'flattened' => $service->encryptFlattened(INTEROP_PAYLOAD),
        ];
    }

    $generalJwe = [];
    foreach ([
        JweKeyManagementAlgorithm::A256KW,
        JweKeyManagementAlgorithm::A256GCMKW,
        JweKeyManagementAlgorithm::RSA_OAEP_256,
        JweKeyManagementAlgorithm::ECDH_ES_A256KW,
    ] as $algorithm) {
        $key = match ($algorithm) {
            JweKeyManagementAlgorithm::A256KW,
            JweKeyManagementAlgorithm::A256GCMKW => $symmetricJwe[$algorithm->value],
            JweKeyManagementAlgorithm::RSA_OAEP_256 => $rsa['public'],
            JweKeyManagementAlgorithm::ECDH_ES_A256KW => $x25519['public'],
            default => throw new LogicException('Unexpected general JWE algorithm.'),
        };
        $generalJwe[$algorithm->value] = new Jwe($key, $algorithm)->encryptGeneral(
            INTEROP_PAYLOAD,
            [['key' => $key, 'kid' => 'interop-recipient']],
        );
    }

    return [
        'payload' => INTEROP_PAYLOAD,
        'keys' => [
            'hmac' => array_map(Base64Url::encode(...), $hmac),
            'rsa' => $rsa,
            'ec' => $ec,
            'ed25519' => [
                'private' => Base64Url::encode($ed['private']),
                'public' => Base64Url::encode($ed['public']),
                'private_jwk' => $jwks->exportOkpPrivateKey($ed['private'], 'interop-eddsa'),
                'public_jwk' => $jwks->exportOkpPublicKey($ed['public'], 'interop-eddsa'),
            ],
            'x25519' => [
                'private' => Base64Url::encode($x25519['private']),
                'public' => Base64Url::encode($x25519['public']),
                'private_jwk' => $jwks->exportOkpPrivateKey(
                    $x25519['private'],
                    'interop-x25519',
                    JweKeyManagementAlgorithm::ECDH_ES->value,
                    'X25519',
                ),
                'public_jwk' => $jwks->exportOkpPublicKey(
                    $x25519['public'],
                    'interop-x25519',
                    JweKeyManagementAlgorithm::ECDH_ES->value,
                    'X25519',
                ),
            ],
            'jwe' => array_map(Base64Url::encode(...), $symmetricJwe),
        ],
        'epicrypt' => [
            'jws' => $jws,
            'jws_general' => Jws::signGeneral(INTEROP_PAYLOAD, [$psSigner, $edSigner]),
            'jws_rfc7797_detached' => $detachedSigner->signFlattened(
                INTEROP_PAYLOAD,
                detached: true,
                base64Payload: false,
            ),
            'jwe' => $jwe,
            'jwe_general' => $generalJwe,
        ],
    ];
}

/** @param array<string, mixed> $fixtures @param array<string, mixed> $candidate */
function assertInteroperable(array $fixtures, array $candidate): void
{
    $keys = $fixtures['keys'];
    if (!is_array($keys)) {
        throw new RuntimeException('Fixture keys are invalid.');
    }
    $jws = $candidate['jws'];
    if (!is_array($jws)) {
        throw new RuntimeException('Candidate JWS values are invalid.');
    }
    foreach (SymmetricJwtAlgorithm::cases() as $algorithm) {
        $key = Base64Url::decode($keys['hmac'][$algorithm->value]);
        assertJwsValues($jws, $algorithm, $key);
    }
    foreach (AsymmetricJwtAlgorithm::cases() as $algorithm) {
        $key = match (true) {
            $algorithm->isEdDsa() => Base64Url::decode($keys['ed25519']['public']),
            str_starts_with($algorithm->value, 'ES') => $keys['ec'][$algorithm->value]['public'],
            default => $keys['rsa']['public'],
        };
        assertJwsValues($jws, $algorithm, $key);
    }

    $general = $candidate['jws_general'] ?? null;
    if (!is_string($general) || !Jws::verifyGeneral($general, [
        Jws::verifier($keys['rsa']['public'], AsymmetricJwtAlgorithm::PS256, 'interop-ps256'),
        Jws::verifier(Base64Url::decode($keys['ed25519']['public']), AsymmetricJwtAlgorithm::EDDSA, 'interop-eddsa'),
    ], 2)) {
        throw new RuntimeException('Independent general JWS was rejected.');
    }
    $detached = $candidate['jws_rfc7797_detached'] ?? null;
    if (!is_string($detached) || !Jws::verifier(
        Base64Url::decode($keys['hmac']['HS256']),
        SymmetricJwtAlgorithm::HS256,
        'interop-rfc7797',
    )->verifyFlattened($detached, INTEROP_PAYLOAD)) {
        throw new RuntimeException('Independent RFC 7797 JWS was rejected.');
    }

    $jwe = $candidate['jwe'];
    if (!is_array($jwe)) {
        throw new RuntimeException('Candidate JWE values are invalid.');
    }
    foreach (JweKeyManagementAlgorithm::cases() as $algorithm) {
        $key = match ($algorithm) {
            JweKeyManagementAlgorithm::DIRECT,
            JweKeyManagementAlgorithm::A256KW,
            JweKeyManagementAlgorithm::A256GCMKW => Base64Url::decode($keys['jwe'][$algorithm->value]),
            JweKeyManagementAlgorithm::RSA_OAEP_256 => $keys['rsa']['private'],
            JweKeyManagementAlgorithm::ECDH_ES,
            JweKeyManagementAlgorithm::ECDH_ES_A256KW => Base64Url::decode($keys['x25519']['private']),
        };
        $service = new Jwe($key, $algorithm, keyId: 'interop-jwe');
        foreach (['compact' => 'decryptCompact', 'flattened' => 'decryptFlattened'] as $serialization => $method) {
            $token = $jwe[$algorithm->value][$serialization] ?? null;
            if (!is_string($token) || $service->{$method}($token) !== INTEROP_PAYLOAD) {
                throw new RuntimeException(sprintf('Independent %s %s was rejected.', $algorithm->value, $serialization));
            }
        }
    }

    $generalJwe = $candidate['jwe_general'] ?? null;
    if (!is_array($generalJwe)) {
        throw new RuntimeException('Candidate general JWE values are invalid.');
    }
    foreach ($generalJwe as $algorithmValue => $token) {
        $algorithm = JweKeyManagementAlgorithm::from($algorithmValue);
        $key = match ($algorithm) {
            JweKeyManagementAlgorithm::A256KW,
            JweKeyManagementAlgorithm::A256GCMKW => Base64Url::decode($keys['jwe'][$algorithm->value]),
            JweKeyManagementAlgorithm::RSA_OAEP_256 => $keys['rsa']['private'],
            JweKeyManagementAlgorithm::ECDH_ES_A256KW => Base64Url::decode($keys['x25519']['private']),
            default => throw new RuntimeException('Unexpected independent general JWE algorithm.'),
        };
        if (!is_string($token) || new Jwe($key, $algorithm)->decryptGeneral($token, 'interop-recipient') !== INTEROP_PAYLOAD) {
            throw new RuntimeException(sprintf('Independent general %s JWE was rejected.', $algorithm->value));
        }
    }
}

/**
 * @param array<string, mixed> $values
 */
function assertJwsValues(
    array $values,
    SymmetricJwtAlgorithm|AsymmetricJwtAlgorithm $algorithm,
    string $key,
): void {
    $verifier = Jws::verifier($key, $algorithm, 'interop-' . strtolower($algorithm->value));
    $compact = $values[$algorithm->value]['compact'] ?? null;
    $flattened = $values[$algorithm->value]['flattened'] ?? null;
    if (!is_string($compact) || !$verifier->verifyCompact($compact)) {
        throw new RuntimeException(sprintf('Independent %s compact JWS was rejected.', $algorithm->value));
    }
    if (!is_string($flattened) || !$verifier->verifyFlattened($flattened)) {
        throw new RuntimeException(sprintf('Independent %s flattened JWS was rejected.', $algorithm->value));
    }
}

$operation = $argv[1] ?? '';
if ($operation === 'produce' && isset($argv[2])) {
    writeDocument($argv[2], produceFixtures());
    fwrite(STDOUT, "Epicrypt JOSE fixtures generated.\n");
} elseif ($operation === 'consume' && isset($argv[2], $argv[3])) {
    assertInteroperable(readDocument($argv[2]), readDocument($argv[3]));
    fwrite(STDOUT, "Independent JOSE fixtures accepted by Epicrypt.\n");
} else {
    throw new InvalidArgumentException(
        'Usage: php tests/Interop/epicrypt.php produce <output> | consume <fixtures> <candidate>',
    );
}
