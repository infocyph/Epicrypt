<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Token\Payload\SignedPayload;

it('verifies the frozen Epicrypt 2.x signed-payload fixture', function () {
    $token = 'eyJhbGciOiJTSEE1MTIiLCJ0eXAiOiJTUFQiLCJ2IjoyLCJjdHgiOiJmaXh0dXJlL3YyIn0.eyJzdWIiOiJ1c2VyLWZpeHR1cmUiLCJwdXIiOiJmaXh0dXJlIiwiaWF0IjoxNzAwMDAwMDAwfQ.XpuHIH0ExtqyDJgL_Q_nwM14fCcGomeGAHnXl9C3UUBpsOwiPk3OwRFkSciHgJYwJGUyuqQCOZFEVaCoNb85Zw';
    $result = new SignedPayload('fixture/v2')->decode(
        $token,
        'signed-payload-secret-32-bytes-minimum',
    );

    expect($result['sub'])->toBe('user-fixture')
        ->and($result['pur'])->toBe('fixture')
        ->and($result['iat'])->toBe(1_700_000_000);
});
