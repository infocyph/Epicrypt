<?php

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\CsrfTokenManager;
use Infocyph\Epicrypt\Security\SignedUrl;

it('uses injected clock for signed payload issuance and verification', function () {
    $issueClock = new class implements ClockInterface
    {
        public function now(): int
        {
            return 1_000;
        }
    };
    $verifyClock = new class implements ClockInterface
    {
        public function now(): int
        {
            return 2_000;
        }
    };

    $issuer = new SignedPayloadCodec('clock-secret', clock: $issueClock);
    $token = $issuer->issue(['sub' => 'user-1'], 1_200);
    $claims = $issuer->verify($token);

    expect($claims['iat'])->toBe(1_000);

    $verifier = new SignedPayloadCodec('clock-secret', clock: $verifyClock);
    expect(fn () => $verifier->verify($token))->toThrow(ExpiredTokenException::class);
});

it('uses injected clock for csrf token expiration claims', function () {
    $clock = new class implements ClockInterface
    {
        public function now(): int
        {
            return 5_000;
        }
    };

    $manager = new CsrfTokenManager('csrf-clock-secret', 60, $clock);
    $token = $manager->issueToken('session-1');
    $claims = (new SignedPayloadCodec('csrf-clock-secret', clock: $clock))->verify($token, 'csrf');

    expect($claims['iat'])->toBe(5_000);
    expect($claims['exp'])->toBe(5_060);
});

it('uses injected clock for signed url expiry validation', function () {
    $clock = new class implements ClockInterface
    {
        public function now(): int
        {
            return 10_000;
        }
    };

    $signedUrl = new SignedUrl('url-secret', clock: $clock);
    $signed = $signedUrl->generate('https://example.com/download', ['file' => 'report'], 9_999);

    expect($signedUrl->verify($signed))->toBeFalse();
});
