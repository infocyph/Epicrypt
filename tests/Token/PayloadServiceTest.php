<?php

use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Token\Payload\SignedPayload;

it('verifies signed payloads against a key ring', function () {
    $payload = new SignedPayload('reset_password');
    $token = $payload->encode(
        ['sub' => 'user-1', 'purpose' => 'reset'],
        'active-secret',
        ['exp' => time() + 600],
    );

    $keyRing = new KeyRing([
        'legacy' => 'legacy-secret',
        'active' => 'active-secret',
    ], 'active');

    $claims = $payload->decodeWithAnyKey($token, $keyRing);
    $result = $payload->verifyWithAnyKeyResult($token, $keyRing);

    expect($claims['sub'])->toBe('user-1');
    expect($payload->verifyWithAnyKey($token, $keyRing))->toBeTrue();
    expect($result->verified)->toBeTrue();
    expect($result->matchedKeyId)->toBe('active');
    expect($result->usedFallbackKey)->toBeFalse();
    expect($payload->verifyWithAnyKey($token, ['wrong-secret']))->toBeFalse();
});
