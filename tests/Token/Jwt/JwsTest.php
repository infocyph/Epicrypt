<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
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
    $rsa = KeyPairGenerator::openSsl()->generate();
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
