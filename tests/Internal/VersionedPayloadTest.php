<?php

use Infocyph\Epicrypt\Internal\VersionedPayload;

it('encodes compact payloads with reserved empty key id marker', function () {
    $payload = VersionedPayload::encodeCompact('epc1', 'secretbox', null, 'nonce', 'ciphertext');
    $parsed = VersionedPayload::parseCompact($payload, 'epc1');

    expect($payload)->toBe('epc1.secretbox._.nonce.ciphertext');
    expect($parsed)->not->toBeNull();
    expect($parsed?->algorithm)->toBe('secretbox');
    expect($parsed?->keyId)->toBeNull();
    expect($parsed?->nonce)->toBe('nonce');
    expect($parsed?->ciphertext)->toBe('ciphertext');
});

it('parses unversioned compact payloads', function () {
    $parsed = VersionedPayload::parseCompact('secretbox.current.nonce.ciphertext', 'epc1');

    expect($parsed)->not->toBeNull();
    expect($parsed?->versioned)->toBeFalse();
    expect($parsed?->algorithm)->toBe('secretbox');
    expect($parsed?->keyId)->toBe('current');
});

it('rejects malformed compact payload parts', function () {
    expect(VersionedPayload::parseCompact('epc1.secretbox._.nonce', 'epc1'))->toBeNull();
    expect(VersionedPayload::parseCompact('epc1.._.nonce.ciphertext', 'epc1'))->toBeNull();
    expect(VersionedPayload::parseCompact('epc1.secretbox._..ciphertext', 'epc1'))->toBeNull();
});

it('rejects invalid compact key id values for encoding', function () {
    expect(fn() => VersionedPayload::encodeCompact('epc1', 'secretbox', '_', 'nonce', 'ciphertext'))
        ->toThrow(InvalidArgumentException::class);
    expect(fn() => VersionedPayload::encodeCompact('epc1', 'secretbox', 'bad.key', 'nonce', 'ciphertext'))
        ->toThrow(InvalidArgumentException::class);
});
