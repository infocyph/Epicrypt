<?php

use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;

it('issues opaque tokens and verifies digests', function () {
    $opaque = new OpaqueToken;
    $token = $opaque->issue(48);
    $digest = $opaque->hash($token);

    expect($token)->toHaveLength(48);
    expect($opaque->verify($token, $digest))->toBeTrue();
    expect($opaque->verify($token . 'x', $digest))->toBeFalse();
});

