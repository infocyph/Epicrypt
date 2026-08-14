<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwe;
use Infocyph\Epicrypt\Token\Jwt\Support\AesKeyWrap;

it('matches the RFC 3394 AES-256 key-wrap vector', function () {
    $kek = hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
    $key = hex2bin('00112233445566778899AABBCCDDEEFF');
    $expected = hex2bin('64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7');
    $wrap = new AesKeyWrap();

    expect($wrap->wrap($kek, $key))->toBe($expected)
        ->and($wrap->unwrap($kek, $expected))->toBe($key);
});

it('bounds and validates standard general JWE recipients', function () {
    $key = random_bytes(32);
    $jwe = new Jwe($key, JweKeyManagementAlgorithm::A256KW);

    expect(fn () => $jwe->encryptGeneral('payload', []))->toThrow(ConfigurationException::class)
        ->and(fn () => $jwe->encryptGeneral(
            'payload',
            array_map(
                static fn (int $index): array => ['key' => random_bytes(32), 'kid' => 'recipient-'.$index],
                range(1, 33),
            ),
        ))->toThrow(ConfigurationException::class)
        ->and(fn () => $jwe->encryptGeneral('payload', [
            ['key' => random_bytes(32), 'kid' => 'duplicate'],
            ['key' => random_bytes(32), 'kid' => 'duplicate'],
        ]))->toThrow(ConfigurationException::class)
        ->and(fn () => new Jwe($key)->encryptGeneral('payload', [['key' => $key, 'kid' => 'one']]))
        ->toThrow(ConfigurationException::class);
});

it('rejects JWE critical compression overlap and corrupt authenticated fields', function () {
    $key = random_bytes(32);
    $jwe = new Jwe($key, JweKeyManagementAlgorithm::A256KW);

    expect(fn () => $jwe->encryptCompact('payload', ['crit' => ['exp']]))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $jwe->encryptCompact('payload', ['zip' => 'DEF']))
        ->toThrow(ConfigurationException::class);

    $valid = $jwe->encryptCompact('payload');
    foreach ([1, 2, 3, 4] as $segment) {
        $parts = explode('.', $valid);
        $parts[$segment] = substr($parts[$segment], 0, -1).($parts[$segment][-1] === 'A' ? 'B' : 'A');
        expect(fn () => $jwe->decryptCompact(implode('.', $parts)))
            ->toThrow(InvalidTokenException::class);
    }

    $general = json_decode($jwe->encryptGeneral('payload', [['key' => $key, 'kid' => 'one']]), true, 32, JSON_THROW_ON_ERROR);
    $general['unprotected'] = ['alg' => 'A256KW'];
    expect(fn () => $jwe->decryptGeneral(json_encode($general, JSON_THROW_ON_ERROR), 'one'))
        ->toThrow(InvalidTokenException::class);
});

it('rejects malformed ECDH agreement party info and ephemeral keys', function () {
    $pair = KeyPairGenerator::sodium()->generate();
    $issuer = new Jwe($pair['public'], JweKeyManagementAlgorithm::ECDH_ES_A256KW);
    $recipient = new Jwe($pair['private'], JweKeyManagementAlgorithm::ECDH_ES_A256KW);
    $parts = explode('.', $issuer->encryptCompact('payload'));
    $header = json_decode(Base64Url::decode($parts[0]), true, 32, JSON_THROW_ON_ERROR);

    foreach ([
        ['apu' => '%'],
        ['apv' => '%'],
        ['epk' => ['kty' => 'OKP', 'crv' => 'X25519', 'x' => 'short']],
    ] as $replacement) {
        $modified = array_replace($header, $replacement);
        $candidate = $parts;
        $candidate[0] = Base64Url::encode(json_encode($modified, JSON_THROW_ON_ERROR));
        expect(fn () => $recipient->decryptCompact(implode('.', $candidate)))
            ->toThrow(InvalidTokenException::class);
    }
});

it('round trips symmetric compact and flattened JWE serializations', function (JweKeyManagementAlgorithm $algorithm) {
    $jwe = new Jwe(random_bytes(32), $algorithm, keyId: 'symmetric-1');
    $compact = $jwe->encryptCompact('private customer record');
    $flattened = $jwe->encryptFlattened('private customer record');

    expect($jwe->decryptCompact($compact))->toBe('private customer record')
        ->and($jwe->decryptFlattened($flattened))->toBe('private customer record');
    if ($algorithm === JweKeyManagementAlgorithm::DIRECT) {
        expect(json_decode($flattened, true, 16, JSON_THROW_ON_ERROR))->not->toHaveKey('encrypted_key');
    }

    $parts = explode('.', $compact);
    $parts[3] = substr($parts[3], 0, -1) . ($parts[3][-1] === 'A' ? 'B' : 'A');
    expect(fn() => $jwe->decryptCompact(implode('.', $parts)))->toThrow(InvalidTokenException::class);
})->with([
    JweKeyManagementAlgorithm::DIRECT,
    JweKeyManagementAlgorithm::A256KW,
    JweKeyManagementAlgorithm::A256GCMKW,
]);

it('round trips RSA OAEP 256 JWE', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $encrypted = new Jwe($pair['public'], JweKeyManagementAlgorithm::RSA_OAEP_256);
    $decrypted = new Jwe($pair['private'], JweKeyManagementAlgorithm::RSA_OAEP_256);
    $token = $encrypted->encryptCompact('rsa protected');

    expect($decrypted->decryptCompact($token))->toBe('rsa protected');
});

it('round trips direct and wrapped X25519 ECDH JWE', function (JweKeyManagementAlgorithm $algorithm) {
    $pair = KeyPairGenerator::sodium()->generate();
    $encrypted = new Jwe($pair['public'], $algorithm);
    $decrypted = new Jwe($pair['private'], $algorithm);
    $token = $encrypted->encryptCompact('ecdh protected', [
        'apu' => sodium_bin2base64('sender', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
        'apv' => sodium_bin2base64('recipient', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
    ]);

    expect($decrypted->decryptCompact($token))->toBe('ecdh protected');
})->with([
    JweKeyManagementAlgorithm::ECDH_ES,
    JweKeyManagementAlgorithm::ECDH_ES_A256KW,
]);

it('supports authenticated recipient selection and nested sign then encrypt', function () {
    $first = random_bytes(32);
    $second = random_bytes(32);
    $issuer = new Jwe($first, JweKeyManagementAlgorithm::A256KW);
    $general = $issuer->encryptGeneral('shared record', [
        ['key' => $first, 'kid' => 'first'],
        ['key' => $second, 'kid' => 'second'],
    ]);

    expect((new Jwe($second, JweKeyManagementAlgorithm::A256KW))->decryptGeneral($general, 'second'))
        ->toBe('shared record');
    $document = json_decode($general, true, 16, JSON_THROW_ON_ERROR);
    $protected = json_decode(\Infocyph\Epicrypt\Internal\Base64Url::decode($document['protected']), true, 16, JSON_THROW_ON_ERROR);
    expect($protected)->not->toHaveKey('kids');

    $nested = new Jwe(random_bytes(32));
    $outer = $nested->encryptNested('header.claims.signature');
    expect($nested->decryptNested($outer))->toBe('header.claims.signature');
});
