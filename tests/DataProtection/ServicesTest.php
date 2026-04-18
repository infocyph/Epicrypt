<?php

use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
use Infocyph\Epicrypt\DataProtection\OpenSSL\InteroperabilityCryptoHelper;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Security\KeyRing;

it('encrypts and decrypts string data safely', function () {
    $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

    $protector = new StringProtector();
    $ciphertext = $protector->encrypt('protected data', $key);
    $plaintext = $protector->decrypt($ciphertext, $key);

    expect($ciphertext)->toStartWith('epc1.');
    expect($plaintext)->toBe('protected data');
});

it('supports key-ring decrypt and re-encryption for protected strings', function () {
    $generator = new KeyMaterialGenerator();
    $legacyKey = $generator->forSecretBox();
    $currentKey = $generator->forSecretBox();

    $protector = new StringProtector();
    $ciphertext = $protector->encrypt('rotating data', $legacyKey);

    $keyRing = new KeyRing([
        'legacy' => $legacyKey,
        'current' => $currentKey,
    ], 'current');

    expect($protector->decryptWithAny($ciphertext, $keyRing))->toBe('rotating data');

    $reprotected = $protector->reencryptWithAny($ciphertext, $keyRing, $currentKey);
    expect($protector->decrypt($reprotected, $currentKey))->toBe('rotating data');
});

it('encrypts and decrypts versioned envelopes', function () {
    $masterKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

    $protector = new EnvelopeProtector();
    $envelope = $protector->encrypt('enveloped data', $masterKey);
    $encoded = $protector->encodeEnvelope($envelope);
    $plaintext = $protector->decrypt($encoded, $masterKey);

    expect($envelope['v'])->toBe(1);
    expect($envelope['alg'])->toBe('secretbox');
    expect($plaintext)->toBe('enveloped data');
});

it('supports envelope re-encryption and compatibility migration helpers', function () {
    $generator = new KeyMaterialGenerator();
    $legacyMaster = $generator->forSecretBox();
    $currentMaster = $generator->forSecretBox();

    $protector = new EnvelopeProtector();
    $encoded = $protector->encodeEnvelope($protector->encrypt('migrated payload', $legacyMaster));

    $migrated = $protector->reencryptWithAny($encoded, ['wrong-key', $legacyMaster], $currentMaster);
    expect($protector->decrypt($migrated, $currentMaster))->toBe('migrated payload');

    $interop = new InteroperabilityCryptoHelper();
    $legacyCipher = $interop->encryptCompatibleString('legacy payload', 'app-secret', 'salt-value');
    $modernCipher = $interop->migrateToStringProtector($legacyCipher, 'app-secret', 'salt-value', $currentMaster);

    expect((new StringProtector())->decrypt($modernCipher, $currentMaster))->toBe('legacy payload');
});
