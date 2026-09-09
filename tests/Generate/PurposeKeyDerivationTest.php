<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;
use Infocyph\Epicrypt\Internal\Base64Url;

it('derives deterministic and domain-separated application subkeys', function () {
    $deriver = new KeyDeriver();
    $master = str_repeat('m', 32);

    $tokenKey = $deriver->derivePurposeKeyBinary($master, 'auth-token', 'foundation');
    $sameTokenKey = $deriver->derivePurposeKeyBinary($master, 'auth-token', 'foundation');
    $sessionKey = $deriver->derivePurposeKeyBinary($master, 'session', 'foundation');
    $recoveryKey = $deriver->derivePurposeKeyBinary($master, 'otp-recovery', 'foundation');
    $otherContext = $deriver->derivePurposeKeyBinary($master, 'auth-token', 'other-app');
    $salted = $deriver->derivePurposeKeyBinary($master, 'auth-token', 'foundation', salt: str_repeat('s', 16));

    expect($tokenKey)->toHaveLength(32)
        ->and($tokenKey)->toBe($sameTokenKey)
        ->and($sessionKey)->not->toBe($tokenKey)
        ->and($recoveryKey)->not->toBe($tokenKey)
        ->and($otherContext)->not->toBe($tokenKey)
        ->and($salted)->not->toBe($tokenKey);
});

it('provides Base64URL purpose-key derivation over the same binary contract', function () {
    $deriver = new KeyDeriver();
    $master = str_repeat('k', 32);
    $salt = str_repeat('z', 16);

    $binary = $deriver->derivePurposeKeyBinary($master, 'oauth-signing', 'foundation', 48, $salt);
    $encoded = $deriver->derivePurposeKey(
        Base64Url::encode($master),
        'oauth-signing',
        'foundation',
        48,
        Base64Url::encode($salt),
    );

    expect(Base64Url::decode($encoded))->toBe($binary)->toHaveLength(48);
});

it('rejects weak masters, ambiguous labels, and unsafe output sizes', function () {
    $deriver = new KeyDeriver();

    expect(fn() => $deriver->derivePurposeKeyBinary('short', 'token'))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => $deriver->derivePurposeKeyBinary(str_repeat('m', 32), ''))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => $deriver->derivePurposeKeyBinary(str_repeat('m', 32), "bad\nlabel"))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => $deriver->derivePurposeKeyBinary(str_repeat('m', 32), 'token', length: 8))
        ->toThrow(ConfigurationException::class);
});
