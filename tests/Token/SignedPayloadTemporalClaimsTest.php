<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;

it('rejects expired signed payloads', function () {
    $codec = new SignedPayloadCodec('signed-payload-secret');
    $token = $codec->issue(['sub' => 'user-1'], time() - 10);

    expect(fn () => $codec->verify($token))->toThrow(ExpiredTokenException::class);
});

it('rejects signed payloads with non-numeric exp claims', function () {
    $codec = new SignedPayloadCodec('signed-payload-secret');
    $token = $codec->issue(['sub' => 'user-1', 'exp' => 'not-a-timestamp']);

    expect(fn () => $codec->verify($token))->toThrow(InvalidTokenException::class);
});

it('rejects signed payloads with non-numeric iat claims', function () {
    $secret = 'signed-payload-secret';
    $header = Base64Url::encode(Json::encode(['alg' => 'SHA512', 'typ' => 'SPT', 'v' => 1]));
    $payload = Base64Url::encode(Json::encode(['sub' => 'user-1', 'iat' => 'not-a-timestamp']));
    $signature = Base64Url::encode(hash_hmac('sha512', $header.'.'.$payload, $secret, true));
    $token = $header.'.'.$payload.'.'.$signature;
    $codec = new SignedPayloadCodec($secret);

    expect(fn () => $codec->verify($token))->toThrow(InvalidTokenException::class);
});

it('accepts signed payloads without exp claims', function () {
    $codec = new SignedPayloadCodec('signed-payload-secret');
    $token = $codec->issue(['sub' => 'user-1']);
    $claims = $codec->verify($token);

    expect($claims['sub'])->toBe('user-1');
});

it('accepts signed payloads with future exp claims', function () {
    $codec = new SignedPayloadCodec('signed-payload-secret');
    $token = $codec->issue(['sub' => 'user-1'], time() + 600);
    $claims = $codec->verify($token);

    expect($claims['sub'])->toBe('user-1');
});

it('rejects tampered signed payloads', function () {
    $codec = new SignedPayloadCodec('signed-payload-secret');
    $token = $codec->issue(['sub' => 'user-1'], time() + 600);

    [$encodedHeader, $encodedPayload, $signature] = explode('.', $token, 3);

    $payload = Json::decodeToArray(Base64Url::decode($encodedPayload));
    $payload['sub'] = 'user-2';
    $tamperedToken = $encodedHeader.'.'.Base64Url::encode(Json::encode($payload)).'.'.$signature;

    expect(fn () => $codec->verify($tamperedToken))->toThrow(InvalidTokenException::class);
});
