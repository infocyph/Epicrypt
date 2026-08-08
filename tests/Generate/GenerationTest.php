<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDerivationContext;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyDeriver;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Generate\NonceGenerator;
use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
use Infocyph\Epicrypt\Generate\SaltGenerator;

it('generates secure material and derives deterministic keys', function () {
    expect((new RandomBytesGenerator())->bytes(32))->not->toBe((new RandomBytesGenerator())->bytes(32))
        ->and((new NonceGenerator())->generate())->not->toBe('')
        ->and((new SaltGenerator())->generate())->not->toBe('')
        ->and((new KeyMaterialGenerator())->forAead())->not->toBe('');

    $context = new KeyDerivationContext(info: 'application-purpose:v1');
    $input = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $deriver = new KeyDeriver();
    expect($deriver->hkdf($input, 32, $context))->toBe($deriver->hkdf($input, 32, $context));
});
