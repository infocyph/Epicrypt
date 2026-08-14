<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jws;

it('supports compact detached and RFC 7797 JWS', function () {
    $key = random_bytes(64);
    $signer = Jws::signer($key, SymmetricJwtAlgorithm::HS512, 'webhook');
    $verifier = Jws::verifier($key, SymmetricJwtAlgorithm::HS512, 'webhook');

    $compact = $signer->signCompact('invoice=42');
    $detached = $signer->signCompact('invoice=42', detached: true);
    $unencoded = $signer->signCompact('invoice=42', detached: true, base64Payload: false);

    expect($verifier->verifyCompact($compact))->toBeTrue()
        ->and($verifier->verifyCompact($detached, 'invoice=42'))->toBeTrue()
        ->and($verifier->verifyCompact($unencoded, 'invoice=42'))->toBeTrue()
        ->and($verifier->verifyCompact($unencoded, 'invoice=43'))->toBeFalse();
});

it('supports flattened and threshold general JWS across algorithms', function () {
    $rsa = KeyPairGenerator::rsa()->generate();
    $ed = KeyPairGenerator::sodiumSign()->generate();
    $rsaSigner = Jws::signer($rsa['private'], AsymmetricJwtAlgorithm::PS256, 'rsa');
    $rsaVerifier = Jws::verifier($rsa['public'], AsymmetricJwtAlgorithm::PS256, 'rsa');
    $edSigner = Jws::signer($ed['private'], AsymmetricJwtAlgorithm::EDDSA, 'ed');
    $edVerifier = Jws::verifier($ed['public'], AsymmetricJwtAlgorithm::EDDSA, 'ed');

    $flattened = $rsaSigner->signFlattened('release-manifest');
    $general = Jws::signGeneral('release-manifest', [$rsaSigner, $edSigner]);

    expect($rsaVerifier->verifyFlattened($flattened))->toBeTrue()
        ->and(Jws::verifyGeneral($general, [$rsaVerifier, $edVerifier], 2))->toBeTrue()
        ->and(Jws::verifyGeneral($general, [$rsaVerifier], 1))->toBeTrue();
});

it('rejects unknown critical headers and protected header confusion', function () {
    $key = random_bytes(32);
    $signer = Jws::signer($key, SymmetricJwtAlgorithm::HS256);
    $verifier = Jws::verifier($key, SymmetricJwtAlgorithm::HS256);
    $valid = json_decode($signer->signFlattened('payload'), true, 8, JSON_THROW_ON_ERROR);
    $valid['header'] = ['alg' => 'HS256'];

    expect($verifier->verifyFlattened(json_encode($valid, JSON_THROW_ON_ERROR)))->toBeFalse();
});

it('distinguishes embedded and detached empty payloads', function () {
    $key = random_bytes(32);
    $signer = Jws::signer($key, SymmetricJwtAlgorithm::HS256);
    $verifier = Jws::verifier($key, SymmetricJwtAlgorithm::HS256);
    $embedded = $signer->signCompact('');
    $detached = $signer->signCompact('', detached: true);
    $flattenedEmbedded = $signer->signFlattened('');
    $flattenedDetached = $signer->signFlattened('', detached: true);

    expect($verifier->verifyCompact($embedded))->toBeTrue()
        ->and($verifier->verifyCompact($detached, ''))->toBeTrue()
        ->and($verifier->verifyFlattened($flattenedEmbedded))->toBeTrue()
        ->and($verifier->verifyFlattened($flattenedDetached, ''))->toBeTrue();
});

it('bounds general JWS signers signatures verifiers and thresholds', function () {
    $key = random_bytes(32);
    $signer = Jws::signer($key, SymmetricJwtAlgorithm::HS256);
    $verifier = Jws::verifier($key, SymmetricJwtAlgorithm::HS256);

    expect(fn () => Jws::signGeneral('payload', []))->toThrow(ConfigurationException::class)
        ->and(fn () => Jws::signGeneral('payload', array_fill(0, 33, $signer)))
        ->toThrow(ConfigurationException::class);

    $general = Jws::signGeneral('payload', [$signer]);
    expect(fn () => Jws::verifyGeneral($general, [], 1))->toThrow(ConfigurationException::class)
        ->and(fn () => Jws::verifyGeneral($general, array_fill(0, 33, $verifier), 1))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => Jws::verifyGeneral($general, [$verifier], 0))
        ->toThrow(ConfigurationException::class);

    $document = json_decode($general, true, 32, JSON_THROW_ON_ERROR);
    $document['signatures'] = array_fill(0, 33, $document['signatures'][0]);
    expect(Jws::verifyGeneral(json_encode($document, JSON_THROW_ON_ERROR), [$verifier], 1))->toBeFalse();
});

it('rejects invalid RFC 7797 header combinations and periods in embedded unencoded payloads', function () {
    $signer = Jws::signer(random_bytes(32), SymmetricJwtAlgorithm::HS256);

    expect(fn () => $signer->signCompact('a.b', base64Payload: false))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $signer->signCompact('payload', ['b64' => false]))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $signer->signCompact('payload', ['crit' => ['unknown']]))
        ->toThrow(ConfigurationException::class);
});
