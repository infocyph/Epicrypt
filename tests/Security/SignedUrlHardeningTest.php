<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\SignedUrl;
use Infocyph\Epicrypt\Security\SignedUrlOptions;
use Psr\Clock\ClockInterface;

function signedUrlClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(public int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@'.$this->timestamp);
        }
    };
}

it('supports method-bound signed urls', function () {
    $signedUrl = new SignedUrl(str_repeat('u', 32));
    $options = new SignedUrlOptions(method: 'POST');
    $signed = $signedUrl->generate('https://example.com/upload', ['file' => 'report'], time() + 300, $options);

    expect($signedUrl->verify($signed, $options))->toBeTrue();
    expect($signedUrl->verify($signed, new SignedUrlOptions(method: 'GET')))->toBeFalse();
});

it('enforces array query parameter policy', function () {
    $signedUrl = new SignedUrl(str_repeat('u', 32));

    expect(fn () => $signedUrl->generate('https://example.com/download?tag[0]=a'))
        ->toThrow(ConfigurationException::class);

    $arrayOptions = new SignedUrlOptions(allowArrayParameters: true);
    $signed = $signedUrl->generate('https://example.com/download?tag[0]=a', options: $arrayOptions);

    expect($signedUrl->verify($signed))->toBeFalse();
    expect($signedUrl->verify($signed, $arrayOptions))->toBeTrue();
});

it('supports host and scheme binding policy controls', function () {
    $signedUrl = new SignedUrl(str_repeat('u', 32));
    $options = new SignedUrlOptions(bindHost: false, bindScheme: false);
    $signed = $signedUrl->generate('https://example.com/download?file=report', expiresAt: time() + 300, options: $options);
    $tamperedHostAndScheme = str_replace('https://example.com', 'http://evil.test', $signed);

    expect($signedUrl->verify($tamperedHostAndScheme, $options))->toBeTrue();
    expect($signedUrl->verify($tamperedHostAndScheme))->toBeFalse();
});

it('enforces absolute/relative and allowed-host policies', function () {
    $signedUrl = new SignedUrl(str_repeat('u', 32));
    $relativeOptions = new SignedUrlOptions(allowAbsoluteUrls: false, allowRelativeUrls: true, bindHost: false, bindScheme: false);
    $signedRelative = $signedUrl->generate('/download/report', expiresAt: time() + 300, options: $relativeOptions);

    expect($signedUrl->verify($signedRelative, $relativeOptions))->toBeTrue();
    expect($signedUrl->verify($signedRelative))->toBeFalse();

    $hostBound = new SignedUrlOptions(allowedHosts: ['example.com']);
    $signedAbsolute = $signedUrl->generate('https://example.com/download', expiresAt: time() + 300, options: $hostBound);

    expect($signedUrl->verify($signedAbsolute, $hostBound))->toBeTrue();
    expect($signedUrl->verify($signedAbsolute, new SignedUrlOptions(allowedHosts: ['api.example.com'])))->toBeFalse();
});

it('rejects reserved names and ambiguous raw query syntax', function () {
    $signedUrl = new SignedUrl(str_repeat('u', 32));
    foreach (['ep_sig', 'ep_exp', 'ep_v', 'ep_m'] as $reserved) {
        expect(fn () => $signedUrl->generate('https://example.com/download?'.$reserved.'=x'))
            ->toThrow(ConfigurationException::class);
        expect(fn () => $signedUrl->generate('https://example.com/download', [$reserved => 'x']))
            ->toThrow(ConfigurationException::class);
    }

    foreach ([
        'a=1&a=2',
        'a=1&%61=2',
        'a.b=1',
        'a+b=1',
        'a=1&a[0]=2',
        'a[0]=1&a[0]=2',
        'a[]=1',
        'a%ZZ=1',
        'a[0][x]=1',
    ] as $query) {
        expect(fn () => $signedUrl->generate('https://example.com/download?'.$query))
            ->toThrow(ConfigurationException::class);
    }

    expect(fn () => new SignedUrl(str_repeat('u', 32), signatureParam: 'same', expiresParam: 'same'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new SignedUrl(str_repeat('u', 32), signatureParam: 'bad.name'))
        ->toThrow(ConfigurationException::class);
});

it('rejects past issuance and expires at the exact configured instant', function () {
    $clock = signedUrlClock(1_700_000_000);
    $signedUrl = new SignedUrl(str_repeat('u', 32), clock: $clock);

    expect(fn () => $signedUrl->generate('https://example.com/download', expiresAt: $clock->timestamp))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $signedUrl->generate('https://example.com/download', expiresAt: $clock->timestamp - 1))
        ->toThrow(ConfigurationException::class);

    $url = $signedUrl->generate('https://example.com/download', expiresAt: $clock->timestamp + 1);
    expect($signedUrl->verify($url))->toBeTrue();
    $clock->timestamp++;
    expect($signedUrl->verify($url))->toBeFalse();
});

it('rejects invalid HTTP method token syntax', function () {
    expect(fn () => new SignedUrlOptions(method: "GET\nPOST"))
        ->toThrow(ConfigurationException::class);
});
