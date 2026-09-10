<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyMaterialEncoding;
use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\KeyPurpose;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

it('generates 32 bytes of master and token entropy in every supported encoding', function () {
    $generator = new KeyMaterialGenerator();

    $rawMaster = $generator->forMasterSecret(KeyMaterialEncoding::RAW);
    $encodedMaster = $generator->forMasterSecret(KeyMaterialEncoding::BASE64URL);
    $hexMaster = $generator->forMasterSecret(KeyMaterialEncoding::HEX);
    $rawToken = $generator->forTokenSecret(KeyMaterialEncoding::RAW);
    $encodedToken = $generator->forTokenSecret(KeyMaterialEncoding::BASE64URL);
    $hexToken = $generator->forTokenSecret(KeyMaterialEncoding::HEX);

    expect(strlen($rawMaster))->toBe(32)
        ->and(strlen($rawToken))->toBe(32)
        ->and(strlen(sodium_base642bin($encodedMaster, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)))->toBe(32)
        ->and(strlen(sodium_base642bin($encodedToken, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)))->toBe(32)
        ->and($encodedMaster)->toMatch('/\A[A-Za-z0-9_-]{43}\z/D')
        ->and($encodedToken)->toMatch('/\A[A-Za-z0-9_-]{43}\z/D')
        ->and($hexMaster)->toMatch('/\A[0-9a-f]{64}\z/D')
        ->and($hexToken)->toMatch('/\A[0-9a-f]{64}\z/D')
        ->and(strlen((string) hex2bin($hexMaster)))->toBe(32)
        ->and(strlen((string) hex2bin($hexToken)))->toBe(32);
});

it('treats requested lengths as raw entropy bytes before encoding', function () {
    $generator = new KeyMaterialGenerator();

    $raw = $generator->generate(17, KeyMaterialEncoding::RAW);
    $encoded = $generator->generate(17, KeyMaterialEncoding::BASE64URL);
    $hex = $generator->generate(17, KeyMaterialEncoding::HEX);

    expect(strlen($raw))->toBe(17)
        ->and(strlen(sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)))->toBe(17)
        ->and($hex)->toMatch('/\A[0-9a-f]{34}\z/D')
        ->and(strlen((string) hex2bin($hex)))->toBe(17)
        ->and(fn () => $generator->generate(0, KeyMaterialEncoding::RAW))
        ->toThrow(ConfigurationException::class);
});

it('uses the canonical encoding boundary for semantic key purposes', function () {
    $generator = new KeyMaterialGenerator();

    $tokenSigning = $generator->forPurpose(KeyPurpose::TOKEN_SIGNING, KeyMaterialEncoding::HEX);
    $wrappedSecret = $generator->forPurpose(KeyPurpose::WRAPPED_SECRET_MASTER, KeyMaterialEncoding::RAW);

    expect($tokenSigning)->toMatch('/\A[0-9a-f]{64}\z/D')
        ->and(strlen($wrappedSecret))->toBe(32);
});

it('produces independent secret material on repeated generation', function () {
    $generator = new KeyMaterialGenerator();

    expect($generator->forTokenSecret(KeyMaterialEncoding::HEX))
        ->not->toBe($generator->forTokenSecret(KeyMaterialEncoding::HEX));
});
