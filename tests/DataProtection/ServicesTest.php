<?php

use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\OpenSSL\InteroperabilityCryptoHelper;
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
    $legacyKey = $generator->forSecretBox();
    $currentKey = $generator->forSecretBox();

    $protector = StringProtector::forProfile(SecurityProfile::MODERN);
    $ciphertext = $protector->encrypt('rotating data', $legacyKey);

    $keyRing = new KeyRing([
        'legacy' => $legacyKey,
        'current' => $currentKey,
    ], 'current');

    $result = $protector->decryptWithAnyKeyResult($ciphertext, $keyRing);

    expect($result->plaintext)->toBe('rotating data');
    expect($result->matchedKeyId)->toBe('legacy');
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

it('supports envelope re-encryption and compatibility migration helpers', function () {
    $generator = new KeyMaterialGenerator();
    $legacyMaster = $generator->forSecretBox();
    $currentMaster = $generator->forSecretBox();

    $protector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
    $encoded = $protector->encodeEnvelope($protector->encrypt('migrated payload', $legacyMaster));

    $result = $protector->decryptWithAnyKeyResult($encoded, ['wrong-key', $legacyMaster]);
    expect($result->plaintext)->toBe('migrated payload');
    expect($result->matchedKeyId)->toBe('1');
    expect($result->usedFallbackKey)->toBeTrue();

    $migrated = $protector->reencryptWithAnyKey($encoded, ['wrong-key', $legacyMaster], $currentMaster);
    expect($protector->decrypt($migrated, $currentMaster))->toBe('migrated payload');

    $interop = new InteroperabilityCryptoHelper();
    $legacyCipher = $interop->encryptCompatibleString('legacy payload', 'app-secret', 'salt-value');
    $modernCipher = $interop->migrateToStringProtector($legacyCipher, 'app-secret', 'salt-value', $currentMaster);

    expect((new StringProtector())->decrypt($modernCipher, $currentMaster))->toBe('legacy payload');
});

it('supports file key rotation and re-encryption migration', function () {
    $generator = new KeyMaterialGenerator();
    $legacyKey = $generator->forSecretStream();
    $currentKey = $generator->forSecretStream();

    $tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'epicrypt-' . bin2hex(random_bytes(6));
    mkdir($tempDir);

    $plain = $tempDir . DIRECTORY_SEPARATOR . 'plain.txt';
    $legacyEncrypted = $tempDir . DIRECTORY_SEPARATOR . 'plain.txt.epc';
    $rotatedEncrypted = $tempDir . DIRECTORY_SEPARATOR . 'plain.txt.rotated.epc';
    $decrypted = $tempDir . DIRECTORY_SEPARATOR . 'plain.dec.txt';

    file_put_contents($plain, 'file migration payload');

    $protector = FileProtector::forProfile(SecurityProfile::MODERN);
    $protector->encrypt($plain, $legacyEncrypted, $legacyKey);

    $result = $protector->reencryptWithAnyKey(
        $legacyEncrypted,
        $rotatedEncrypted,
        new KeyRing(['legacy' => $legacyKey, 'current' => $currentKey], 'current'),
        $currentKey,
    );

    $protector->decrypt($rotatedEncrypted, $decrypted, $currentKey);

    expect($result->outputPath)->toBe($rotatedEncrypted);
    expect($result->matchedKeyId)->toBe('legacy');
    expect($result->usedFallbackKey)->toBeTrue();
    expect(file_get_contents($decrypted))->toBe('file migration payload');

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

it('blocks profile-aware data-protection writes in legacy-decrypt-only mode', function () {
    $generator = new KeyMaterialGenerator();
    $key = $generator->forSecretBox();
    $masterKey = $generator->forSecretBox();
    $plainFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'epicrypt-legacy-' . bin2hex(random_bytes(6)) . '.txt';
    file_put_contents($plainFile, 'legacy-only payload');

    $stringProtector = StringProtector::forProfile(SecurityProfile::LEGACY_DECRYPT_ONLY);
    $envelopeProtector = EnvelopeProtector::forProfile(SecurityProfile::LEGACY_DECRYPT_ONLY);
    $fileProtector = FileProtector::forProfile(SecurityProfile::LEGACY_DECRYPT_ONLY);

    try {
        expect(fn () => $stringProtector->encrypt('payload', $key))
            ->toThrow('String protection writes are disabled for the legacy-decrypt-only profile.');
        expect(fn () => $envelopeProtector->encrypt('payload', $masterKey))
            ->toThrow('Envelope encryption is disabled for the legacy-decrypt-only profile.');
        expect(fn () => $fileProtector->encrypt($plainFile, $plainFile . '.epc', $generator->forSecretStream()))
            ->toThrow('File encryption is disabled for the legacy-decrypt-only profile.');
    } finally {
        if (file_exists($plainFile)) {
            unlink($plainFile);
        }
    }
});

it('still allows profile-aware data-protection reads in legacy-decrypt-only mode', function () {
    $generator = new KeyMaterialGenerator();
    $stringKey = $generator->forSecretBox();
    $masterKey = $generator->forSecretBox();
    $fileKey = $generator->forSecretStream();

    $modernString = StringProtector::forProfile(SecurityProfile::MODERN);
    $modernEnvelope = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
    $legacyReadOnlyString = StringProtector::forProfile(SecurityProfile::LEGACY_DECRYPT_ONLY);
    $legacyReadOnlyEnvelope = EnvelopeProtector::forProfile(SecurityProfile::LEGACY_DECRYPT_ONLY);
    $legacyReadOnlyFile = FileProtector::forProfile(SecurityProfile::LEGACY_DECRYPT_ONLY);

    $ciphertext = $modernString->encrypt('legacy-readable-string', $stringKey);
    expect($legacyReadOnlyString->decrypt($ciphertext, $stringKey))->toBe('legacy-readable-string');

    $encodedEnvelope = $modernEnvelope->encodeEnvelope($modernEnvelope->encrypt('legacy-readable-envelope', $masterKey));
    expect($legacyReadOnlyEnvelope->decrypt($encodedEnvelope, $masterKey))->toBe('legacy-readable-envelope');

    $tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'epicrypt-read-' . bin2hex(random_bytes(6));
    mkdir($tempDir);

    $plain = $tempDir . DIRECTORY_SEPARATOR . 'plain.txt';
    $encrypted = $tempDir . DIRECTORY_SEPARATOR . 'plain.txt.epc';
    $decrypted = $tempDir . DIRECTORY_SEPARATOR . 'plain.dec.txt';

    file_put_contents($plain, 'legacy-readable-file');

    try {
        FileProtector::forProfile(SecurityProfile::MODERN)->encrypt($plain, $encrypted, $fileKey);
        $legacyReadOnlyFile->decrypt($encrypted, $decrypted, $fileKey);

        expect(file_get_contents($decrypted))->toBe('legacy-readable-file');
    } finally {
        if (PHP_OS_FAMILY === 'Windows') {
            return;
        }

        if (is_dir($tempDir)) {
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

            $remaining = array_diff(scandir($tempDir) ?: [], ['.', '..']);
            foreach ($remaining as $entry) {
                $path = $tempDir . DIRECTORY_SEPARATOR . $entry;
                if (is_dir($path)) {
                    if (!rmdir($path) && is_dir($path)) {
                        continue;
                    }
                    continue;
                }

                if (!unlink($path) && file_exists($path)) {
                    continue;
                }
            }

            if (!rmdir($tempDir) && is_dir($tempDir)) {
                return;
            }
        }
    }
});
