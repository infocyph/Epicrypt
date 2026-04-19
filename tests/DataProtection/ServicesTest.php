<?php

use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

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
    $previousKey = $generator->forSecretBox();
    $currentKey = $generator->forSecretBox();

    $protector = StringProtector::forProfile();
    $ciphertext = $protector->encrypt('rotating data', $previousKey);

    $keyRing = new KeyRing([
        'previous' => $previousKey,
        'current' => $currentKey,
    ], 'current');

    $result = $protector->decryptWithAnyKeyResult($ciphertext, $keyRing);

    expect($result->plaintext)->toBe('rotating data');
    expect($result->matchedKeyId)->toBe('previous');
    expect($result->usedFallbackKey)->toBeTrue();

    $reprotected = $protector->reencryptWithAnyKey($ciphertext, $keyRing, $currentKey);
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

it('supports envelope re-encryption across key rotation', function () {
    $generator = new KeyMaterialGenerator();
    $previousMaster = $generator->forSecretBox();
    $currentMaster = $generator->forSecretBox();

    $protector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
    $encoded = $protector->encodeEnvelope($protector->encrypt('rotated payload', $previousMaster));

    $result = $protector->decryptWithAnyKeyResult($encoded, ['wrong-key', $previousMaster]);
    expect($result->plaintext)->toBe('rotated payload');
    expect($result->matchedKeyId)->toBe('1');
    expect($result->usedFallbackKey)->toBeTrue();

    $rotated = $protector->reencryptWithAnyKey($encoded, ['wrong-key', $previousMaster], $currentMaster);
    expect($protector->decrypt($rotated, $currentMaster))->toBe('rotated payload');
});

it('supports file key rotation and re-encryption', function () {
    $generator = new KeyMaterialGenerator();
    $previousKey = $generator->forSecretStream();
    $currentKey = $generator->forSecretStream();

    $tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'epicrypt-' . bin2hex(random_bytes(6));
    mkdir($tempDir);

    $plain = $tempDir . DIRECTORY_SEPARATOR . 'plain.txt';
    $previousEncrypted = $tempDir . DIRECTORY_SEPARATOR . 'plain.txt.epc';
    $rotatedEncrypted = $tempDir . DIRECTORY_SEPARATOR . 'plain.txt.rotated.epc';
    $decrypted = $tempDir . DIRECTORY_SEPARATOR . 'plain.dec.txt';

    file_put_contents($plain, 'file rotation payload');

    $protector = FileProtector::forProfile(SecurityProfile::MODERN);
    $protector->encrypt($plain, $previousEncrypted, $previousKey);

    $result = $protector->reencryptWithAnyKey(
        $previousEncrypted,
        $rotatedEncrypted,
        new KeyRing(['previous' => $previousKey, 'current' => $currentKey], 'current'),
        $currentKey,
    );

    $protector->decrypt($rotatedEncrypted, $decrypted, $currentKey);

    expect($result->outputPath)->toBe($rotatedEncrypted);
    expect($result->matchedKeyId)->toBe('previous');
    expect($result->usedFallbackKey)->toBeTrue();
    expect(file_get_contents($decrypted))->toBe('file rotation payload');

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($tempDir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $entry) {
        if ($entry->isDir()) {
            rmdir($entry->getPathname());
            continue;
        }

        unlink($entry->getPathname());
    }
});
