<?php

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
