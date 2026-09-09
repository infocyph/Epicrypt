<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwe;
use Infocyph\Epicrypt\Token\Jwt\Jws;
use Infocyph\Epicrypt\Token\Jwt\Support\JosePolicy;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;

it('resolves registered JOSE algorithm identifiers exactly', function () {
    expect(AsymmetricJwtAlgorithm::fromHeader('EdDSA'))->toBe(AsymmetricJwtAlgorithm::EDDSA)
        ->and(AsymmetricJwtAlgorithm::fromHeader('PS256'))->toBe(AsymmetricJwtAlgorithm::PS256)
        ->and(SymmetricJwtAlgorithm::fromHeader('HS256'))->toBe(SymmetricJwtAlgorithm::HS256)
        ->and(fn () => AsymmetricJwtAlgorithm::fromHeader('eddsa'))->toThrow(UnsupportedAlgorithmException::class)
        ->and(fn () => SymmetricJwtAlgorithm::fromHeader('hs256'))->toThrow(UnsupportedAlgorithmException::class);
});

it('enforces algorithm-specific symmetric key floors centrally', function () {
    expect(SymmetricJwtAlgorithm::HS256->minimumKeyBytes())->toBe(32)
        ->and(SymmetricJwtAlgorithm::HS384->minimumKeyBytes())->toBe(48)
        ->and(SymmetricJwtAlgorithm::HS512->minimumKeyBytes())->toBe(64)
        ->and(fn () => Jws::signer(str_repeat('k', 47), SymmetricJwtAlgorithm::HS384))
        ->toThrow(ConfigurationException::class)
        ->and(Jws::signer(str_repeat('k', 48), SymmetricJwtAlgorithm::HS384))
        ->toBeInstanceOf(Jws::class);
});

it('bounds compact JWS input and generated serialization', function () {
    $key = str_repeat('k', 32);
    $signer = Jws::signer($key, SymmetricJwtAlgorithm::HS256, 'sig-1');
    $verifier = Jws::verifier($key, SymmetricJwtAlgorithm::HS256, 'sig-1');

    expect($verifier->verifyCompact(str_repeat('x', JosePolicy::MAX_COMPACT_TOKEN_BYTES + 1)))->toBeFalse()
        ->and(fn () => $signer->signCompact(str_repeat('x', JosePolicy::MAX_COMPACT_TOKEN_BYTES)))
        ->toThrow(ConfigurationException::class);
});

it('bounds protected header member counts before signing or encryption', function () {
    $headers = [];
    for ($index = 0; $index < JosePolicy::MAX_HEADER_MEMBERS; $index++) {
        $headers['h' . $index] = 'v';
    }

    expect(fn () => Jws::signer(str_repeat('k', 32), SymmetricJwtAlgorithm::HS256)->signCompact('payload', $headers))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => (new Jwe(random_bytes(32)))->encryptCompact('payload', $headers))
        ->toThrow(ConfigurationException::class);
});

it('rejects excessive JOSE JSON depth and member counts', function () {
    $deep = str_repeat('{"a":', JosePolicy::MAX_JSON_DEPTH + 2)
        . '"value"'
        . str_repeat('}', JosePolicy::MAX_JSON_DEPTH + 2);

    $members = [];
    for ($index = 0; $index <= JosePolicy::MAX_DOCUMENT_MEMBERS; $index++) {
        $members['m' . $index] = $index;
    }
    $wide = json_encode($members, JSON_THROW_ON_ERROR);

    expect(fn () => JwtToken::decodeJsonObject($deep, 'test document'))
        ->toThrow(InvalidTokenException::class)
        ->and(fn () => JwtToken::decodeJsonObject(
            $wide,
            'test document',
            JosePolicy::MAX_COMPACT_TOKEN_BYTES,
            JosePolicy::MAX_DOCUMENT_MEMBERS,
        ))->toThrow(InvalidTokenException::class);
});

it('uses one JOSE key-id grammar across JWS and JWE configuration', function () {
    $invalidKid = 'not allowed';

    expect(fn () => Jws::signer(str_repeat('k', 32), SymmetricJwtAlgorithm::HS256, $invalidKid))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new Jwe(random_bytes(32), keyId: $invalidKid))
        ->toThrow(ConfigurationException::class)
        ->and(JosePolicy::isKeyId(str_repeat('a', JosePolicy::MAX_KEY_ID_BYTES)))->toBeTrue()
        ->and(JosePolicy::isKeyId(str_repeat('a', JosePolicy::MAX_KEY_ID_BYTES + 1)))->toBeFalse();
});
