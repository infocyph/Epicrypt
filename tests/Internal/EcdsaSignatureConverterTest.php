<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\Token\SignatureEncodingException;
use Infocyph\Epicrypt\Internal\EcdsaSignatureConverter;

it('throws typed exception for invalid asn1 signatures', function () {
    $converter = new EcdsaSignatureConverter;

    expect(fn () => $converter->fromAsn1('not-asn1', 64))->toThrow(SignatureEncodingException::class);
});

it('throws typed exception for invalid jose signature length', function () {
    $converter = new EcdsaSignatureConverter;

    expect(fn () => $converter->toAsn1(random_bytes(10), 64))->toThrow(SignatureEncodingException::class);
});

it('rejects DER lengths outside the supported two-octet encoding', function () {
    $converter = new EcdsaSignatureConverter();
    $oversized = str_repeat("\x01", 65_536);

    expect(fn () => $converter->toAsn1($oversized, strlen($oversized)))
        ->toThrow(SignatureEncodingException::class);
});

it('round trips canonical ECDSA signatures and rejects non-canonical DER', function () {
    $converter = new EcdsaSignatureConverter();
    $raw = str_repeat("\x01", 32).str_repeat("\x80", 32);
    $der = $converter->toAsn1($raw, 64);
    expect($converter->fromAsn1($der, 64))->toBe($raw);

    foreach ([
        $der."\x00",                         // trailing data
        "\x30\x80\x02\x01\x01\x02\x01\x01\x00\x00", // indefinite length
        "\x30\x06\x02\x01\x80\x02\x01\x01", // negative r
        "\x30\x07\x02\x02\x00\x01\x02\x01\x01", // redundant integer zero
        "\x30\x05\x02\x00\x02\x01\x01", // empty r
        "\x30\x06\x02\x01\x00\x02\x01\x01", // zero r
        "\x31\x06\x02\x01\x01\x02\x01\x01", // wrong sequence tag
        "\x30\x06\x03\x01\x01\x02\x01\x01", // wrong integer tag
    ] as $invalid) {
        expect(fn () => $converter->fromAsn1($invalid, 64))
            ->toThrow(SignatureEncodingException::class);
    }
});
