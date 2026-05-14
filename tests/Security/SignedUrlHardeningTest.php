<?php

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\SignedUrl;
use Infocyph\Epicrypt\Security\SignedUrlOptions;

it('supports method-bound signed urls', function () {
    $signedUrl = new SignedUrl('url-secret');
    $options = new SignedUrlOptions(method: 'POST');
    $signed = $signedUrl->generate('https://example.com/upload', ['file' => 'report'], time() + 300, $options);

    expect($signedUrl->verify($signed, $options))->toBeTrue();
    expect($signedUrl->verify($signed, new SignedUrlOptions(method: 'GET')))->toBeFalse();
});

it('enforces array query parameter policy', function () {
    $signedUrl = new SignedUrl('url-secret');

    expect(fn () => $signedUrl->generate('https://example.com/download?tag[]=a'))
        ->toThrow(ConfigurationException::class);

    $arrayOptions = new SignedUrlOptions(allowArrayParameters: true);
    $signed = $signedUrl->generate('https://example.com/download?tag[]=a', options: $arrayOptions);

    expect($signedUrl->verify($signed))->toBeFalse();
    expect($signedUrl->verify($signed, $arrayOptions))->toBeTrue();
});

it('supports host and scheme binding policy controls', function () {
    $signedUrl = new SignedUrl('url-secret');
    $options = new SignedUrlOptions(bindHost: false, bindScheme: false);
    $signed = $signedUrl->generate('https://example.com/download?file=report', expiresAt: time() + 300, options: $options);
    $tamperedHostAndScheme = str_replace('https://example.com', 'http://evil.test', $signed);

    expect($signedUrl->verify($tamperedHostAndScheme, $options))->toBeTrue();
    expect($signedUrl->verify($tamperedHostAndScheme))->toBeFalse();
});

it('enforces absolute/relative and allowed-host policies', function () {
    $signedUrl = new SignedUrl('url-secret');
    $relativeOptions = new SignedUrlOptions(allowAbsoluteUrls: false, allowRelativeUrls: true, bindHost: false, bindScheme: false);
    $signedRelative = $signedUrl->generate('/download/report', expiresAt: time() + 300, options: $relativeOptions);

    expect($signedUrl->verify($signedRelative, $relativeOptions))->toBeTrue();
    expect($signedUrl->verify($signedRelative))->toBeFalse();

    $hostBound = new SignedUrlOptions(allowedHosts: ['example.com']);
    $signedAbsolute = $signedUrl->generate('https://example.com/download', expiresAt: time() + 300, options: $hostBound);

    expect($signedUrl->verify($signedAbsolute, $hostBound))->toBeTrue();
    expect($signedUrl->verify($signedAbsolute, new SignedUrlOptions(allowedHosts: ['api.example.com'])))->toBeFalse();
});
