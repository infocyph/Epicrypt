<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;
use Infocyph\Epicrypt\Exception\ConfigurationException;

it('issues opaque tokens and verifies digests', function () {
    $opaque = new OpaqueToken;
    $token = $opaque->issue(48);
    $digest = $opaque->hash($token);

    expect($token)->toHaveLength(48);
    expect($opaque->verify($token, $digest))->toBeTrue();
    expect($opaque->verify($token.'x', $digest))->toBeFalse();
});

it('rejects opaque tokens below the security floor or above the size bound', function () {
    $opaque = new OpaqueToken;

    expect(fn() => $opaque->issue(OpaqueToken::MINIMUM_LENGTH - 1))->toThrow(ConfigurationException::class)
        ->and(fn() => $opaque->issue(OpaqueToken::MAXIMUM_LENGTH + 1))->toThrow(ConfigurationException::class)
        ->and($opaque->verify('short', str_repeat('0', 64)))->toBeFalse()
        ->and($opaque->verify($opaque->issue(), 'invalid-digest'))->toBeFalse();
});
