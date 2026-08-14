<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Token\Payload\SignedPayload;

const SIGNED_PAYLOAD_TEST_SECRET = 'signed-payload-secret-32-bytes-minimum';

it('rejects expired signed payloads', function () {
    $codec = new SignedPayloadCodec(SIGNED_PAYLOAD_TEST_SECRET);
    $token = $codec->issue(['sub' => 'user-1']);
    [$header, $payload] = explode('.', $token);
    $claims = Json::decodeToArray(Base64Url::decode($payload));
    $claims['exp'] = $claims['iat'];
    $payload = Base64Url::encode(Json::encode($claims));
    $signature = Base64Url::encode(hash_hmac('sha512', $header . '.' . $payload, SIGNED_PAYLOAD_TEST_SECRET, true));

    expect(fn () => $codec->verify($header . '.' . $payload . '.' . $signature))->toThrow(ExpiredTokenException::class);
});

it('rejects signed payloads with non-numeric exp claims', function () {
    $header = Base64Url::encode(Json::encode(['alg' => 'SHA512', 'typ' => 'SPT', 'v' => 2]));
    $payload = Base64Url::encode(Json::encode(['sub' => 'user-1', 'iat' => time(), 'exp' => 'not-a-timestamp']));
    $signature = Base64Url::encode(hash_hmac('sha512', $header.'.'.$payload, SIGNED_PAYLOAD_TEST_SECRET, true));
    $token = $header.'.'.$payload.'.'.$signature;
    $codec = new SignedPayloadCodec(SIGNED_PAYLOAD_TEST_SECRET);

    expect(fn () => $codec->verify($token))->toThrow(InvalidTokenException::class);
});

it('uses only the explicit expiration parameter and replaces caller temporal issuance claims', function () {
    $payloads = new SignedPayload('checkout/v1');
    $token = $payloads->encode(
        ['sub' => 'user-1', 'iat' => 1, 'exp' => 2],
        SIGNED_PAYLOAD_TEST_SECRET,
        time() + 600,
    );
    $claims = $payloads->decode($token, SIGNED_PAYLOAD_TEST_SECRET);

    expect($claims['iat'])->toBeGreaterThan(1)
        ->and($claims['exp'])->toBeGreaterThan(time());
});

it('rejects signed payloads with non-numeric iat claims', function () {
    $secret = SIGNED_PAYLOAD_TEST_SECRET;
    $header = Base64Url::encode(Json::encode(['alg' => 'SHA512', 'typ' => 'SPT', 'v' => 2]));
    $payload = Base64Url::encode(Json::encode(['sub' => 'user-1', 'iat' => 'not-a-timestamp']));
    $signature = Base64Url::encode(hash_hmac('sha512', $header.'.'.$payload, $secret, true));
    $token = $header.'.'.$payload.'.'.$signature;
    $codec = new SignedPayloadCodec($secret);

    expect(fn () => $codec->verify($token))->toThrow(InvalidTokenException::class);
});

it('accepts signed payloads without exp claims', function () {
    $codec = new SignedPayloadCodec(SIGNED_PAYLOAD_TEST_SECRET);
    $token = $codec->issue(['sub' => 'user-1']);
    $claims = $codec->verify($token);

    expect($claims['sub'])->toBe('user-1');
});

it('accepts signed payloads with future exp claims', function () {
    $codec = new SignedPayloadCodec(SIGNED_PAYLOAD_TEST_SECRET);
    $token = $codec->issue(['sub' => 'user-1'], time() + 600);
    $claims = $codec->verify($token);

    expect($claims['sub'])->toBe('user-1');
});

it('rejects tampered signed payloads', function () {
    $codec = new SignedPayloadCodec(SIGNED_PAYLOAD_TEST_SECRET);
    $token = $codec->issue(['sub' => 'user-1'], time() + 600);

    [$encodedHeader, $encodedPayload, $signature] = explode('.', $token, 3);

    $payload = Json::decodeToArray(Base64Url::decode($encodedPayload));
    $payload['sub'] = 'user-2';
    $tamperedToken = $encodedHeader.'.'.Base64Url::encode(Json::encode($payload)).'.'.$signature;

    expect(fn () => $codec->verify($tamperedToken))->toThrow(InvalidTokenException::class);
});
