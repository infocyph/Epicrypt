<?php

use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionAad;
use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

it('encrypts and decrypts string data safely', function () {
    $key = (new KeyMaterialGenerator)->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

    $protector = new StringProtector;
    $ciphertext = $protector->encrypt('protected data', $key);
    $plaintext = $protector->decrypt($ciphertext, $key);
    $segments = explode('.', $ciphertext);

    expect($ciphertext)->toStartWith('epc1.');
    expect($segments)->toHaveCount(5);
    expect($segments[1])->toBe('secretbox');
    expect($segments[2])->toBe('_');
    expect($plaintext)->toBe('protected data');
});

it('supports key-ring decrypt and re-encryption for protected strings', function () {
    $generator = new KeyMaterialGenerator;
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

it('embeds and resolves key ids for protected strings with key rings', function () {
    $generator = new KeyMaterialGenerator;
    $previousKey = $generator->forSecretBox();
    $currentKey = $generator->forSecretBox();

    $keyRing = new KeyRing([
        'previous' => $previousKey,
        'current' => $currentKey,
    ], 'current');

    $protector = StringProtector::forProfile();
    $ciphertext = $protector->encryptWithKeyRing('rotating data', $keyRing);
    $segments = explode('.', $ciphertext);
    $result = $protector->decryptWithKeyRingResult($ciphertext, $keyRing);

    expect($segments[1])->toBe('secretbox');
    expect($segments[2])->toBe('current');
    expect($result->plaintext)->toBe('rotating data');
    expect($result->matchedKeyId)->toBe('current');
    expect($result->usedFallbackKey)->toBeFalse();
});

it('fails protected string key-ring decrypt when payload key id is missing', function () {
    $generator = new KeyMaterialGenerator;
    $currentKey = $generator->forSecretBox();
    $ciphertext = StringProtector::forProfile()->encrypt('rotating data', $currentKey, ['key_id' => 'missing-id']);

    $keyRing = new KeyRing([
        'current' => $currentKey,
    ], 'current');

    expect(fn() => StringProtector::forProfile()->decryptWithKeyRingResult($ciphertext, $keyRing))
        ->toThrow(DecryptionException::class);
});

it('does not fallback for protected strings when key id is present but key is wrong', function () {
    $generator = new KeyMaterialGenerator;
    $previousKey = $generator->forSecretBox();
    $wrongCurrentKey = $generator->forSecretBox();

    $keyRing = new KeyRing([
        'previous' => $previousKey,
        'current' => $wrongCurrentKey,
    ], 'current');

    $ciphertext = StringProtector::forProfile()->encrypt('rotating data', $previousKey, ['key_id' => 'current']);

    expect(fn() => StringProtector::forProfile()->decryptWithKeyRingResult($ciphertext, $keyRing))
        ->toThrow(DecryptionException::class);
});

it('encrypts and decrypts versioned envelopes', function () {
    $masterKey = (new KeyMaterialGenerator)->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

    $protector = new EnvelopeProtector;
    $envelope = $protector->encrypt('enveloped data', $masterKey);
    $encoded = $protector->encodeEnvelope($envelope);
    $plaintext = $protector->decrypt($encoded, $masterKey);

    expect($envelope['v'])->toBe(1);
    expect($envelope['alg'])->toBe('secretbox');
    expect($envelope['dek_alg'])->toBe('secretbox');
    expect($envelope['created_at'])->toBeInt();
    expect($plaintext)->toBe('enveloped data');
});

it('supports envelope re-encryption across key rotation', function () {
    $generator = new KeyMaterialGenerator;
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

it('embeds and resolves key ids for envelopes with key rings', function () {
    $generator = new KeyMaterialGenerator;
    $previousMaster = $generator->forSecretBox();
    $currentMaster = $generator->forSecretBox();
    $keyRing = new KeyRing([
        'previous' => $previousMaster,
        'current' => $currentMaster,
    ], 'current');

    $protector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
    $envelope = $protector->encryptWithKeyRing('rotated payload', $keyRing, ['purpose' => 'merchant.secret']);
    $encoded = $protector->encodeEnvelope($envelope);
    $result = $protector->decryptWithKeyRingResult($encoded, $keyRing);

    expect($envelope['kid'])->toBe('current');
    expect($envelope['purpose'])->toBe('merchant.secret');
    expect($result->plaintext)->toBe('rotated payload');
    expect($result->matchedKeyId)->toBe('current');
    expect($result->usedFallbackKey)->toBeFalse();
    expect($result->dekAlgorithm)->toBe('secretbox');
    expect($result->createdAt)->toBeInt();
    expect($result->purpose)->toBe('merchant.secret');
});

it('does not fallback for envelopes when key id is present but key is wrong', function () {
    $generator = new KeyMaterialGenerator;
    $previousMaster = $generator->forSecretBox();
    $wrongCurrentMaster = $generator->forSecretBox();
    $keyRing = new KeyRing([
        'previous' => $previousMaster,
        'current' => $wrongCurrentMaster,
    ], 'current');

    $protector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
    $envelope = $protector->encrypt('rotated payload', $previousMaster);
    $envelope['kid'] = 'current';
    $encoded = $protector->encodeEnvelope($envelope);

    expect(fn() => $protector->decryptWithKeyRingResult($encoded, $keyRing))
        ->toThrow(DecryptionException::class);
});

it('supports file key rotation and re-encryption', function () {
    $generator = new KeyMaterialGenerator;
    $previousKey = $generator->forSecretStream();
    $currentKey = $generator->forSecretStream();

    $tempDir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'epicrypt-'.bin2hex(random_bytes(6));
    mkdir($tempDir);

    $plain = $tempDir.DIRECTORY_SEPARATOR.'plain.txt';
    $previousEncrypted = $tempDir.DIRECTORY_SEPARATOR.'plain.txt.epc';
    $rotatedEncrypted = $tempDir.DIRECTORY_SEPARATOR.'plain.txt.rotated.epc';
    $decrypted = $tempDir.DIRECTORY_SEPARATOR.'plain.dec.txt';

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

    cleanupServicesTempDirectory($tempDir);
});

it('supports safe in-place file key rotation', function () {
    $generator = new KeyMaterialGenerator;
    $previousKey = $generator->forSecretStream();
    $currentKey = $generator->forSecretStream();

    $tempDir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'epicrypt-'.bin2hex(random_bytes(6));
    mkdir($tempDir);

    $plain = $tempDir.DIRECTORY_SEPARATOR.'plain.txt';
    $encryptedPath = $tempDir.DIRECTORY_SEPARATOR.'payload.epc';
    $decrypted = $tempDir.DIRECTORY_SEPARATOR.'plain.dec.txt';

    file_put_contents($plain, 'file in-place rotation payload');

    $protector = FileProtector::forProfile(SecurityProfile::MODERN);
    $protector->encrypt($plain, $encryptedPath, $previousKey);
    $beforeRotation = file_get_contents($encryptedPath);

    $result = $protector->reencryptInPlaceWithAnyKey(
        $encryptedPath,
        new KeyRing(['previous' => $previousKey, 'current' => $currentKey], 'current'),
        $currentKey,
    );

    $afterRotation = file_get_contents($encryptedPath);
    $protector->decrypt($encryptedPath, $decrypted, $currentKey);

    expect($result->outputPath)->toBe($encryptedPath);
    expect($result->matchedKeyId)->toBe('previous');
    expect($result->usedFallbackKey)->toBeTrue();
    expect($beforeRotation)->not->toBe($afterRotation);
    expect(file_get_contents($decrypted))->toBe('file in-place rotation payload');

    cleanupServicesTempDirectory($tempDir);
});

it('rolls back in-place file key rotation when final rename fails', function () {
    $generator = new KeyMaterialGenerator;
    $previousKey = $generator->forSecretStream();
    $currentKey = $generator->forSecretStream();

    $tempDir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'epicrypt-'.bin2hex(random_bytes(6));
    mkdir($tempDir);

    $plain = $tempDir.DIRECTORY_SEPARATOR.'plain.txt';
    $encryptedPath = $tempDir.DIRECTORY_SEPARATOR.'payload.epc';
    $decrypted = $tempDir.DIRECTORY_SEPARATOR.'plain.dec.txt';

    file_put_contents($plain, 'file rollback payload');

    $baselineProtector = FileProtector::forProfile(SecurityProfile::MODERN);
    $baselineProtector->encrypt($plain, $encryptedPath, $previousKey);
    $beforeRotation = file_get_contents($encryptedPath);

    $renameCount = 0;
    $failingProtector = new FileProtector(
        renameOperation: static function (string $from, string $to) use (&$renameCount, $encryptedPath): bool {
            $renameCount++;
            if ($renameCount === 2 && $to === $encryptedPath) {
                return false;
            }

            return rename($from, $to);
        },
    );

    expect(fn() => $failingProtector->reencryptInPlaceWithAnyKey(
        $encryptedPath,
        new KeyRing(['previous' => $previousKey, 'current' => $currentKey], 'current'),
        $currentKey,
    ))->toThrow(FileAccessException::class);

    $afterFailure = file_get_contents($encryptedPath);
    $baselineProtector->decrypt($encryptedPath, $decrypted, $previousKey);

    expect($afterFailure)->toBe($beforeRotation);
    expect(file_get_contents($decrypted))->toBe('file rollback payload');

    cleanupServicesTempDirectory($tempDir);
});

it('builds deterministic protection aad values', function () {
    expect(ProtectionAad::forString('user.email', 'v1'))->toBe('epicrypt:string:user.email:v1');
    expect(ProtectionAad::forFile('backup.archive', 'v1'))->toBe('epicrypt:file:backup.archive:v1');
    expect(ProtectionAad::forEnvelope('merchant.secret', 'v1'))->toBe('epicrypt:envelope:merchant.secret:v1');
});

it('supports inspect and rotation helper methods', function () {
    $generator = new KeyMaterialGenerator;
    $previousKey = $generator->forSecretBox();
    $currentKey = $generator->forSecretBox();

    $keyRing = new KeyRing([
        'previous' => $previousKey,
        'current' => $currentKey,
    ], 'current');

    $stringProtector = StringProtector::forProfile();
    $ciphertext = $stringProtector->encryptWithKeyRing('rotating data', $keyRing);
    $stringInfo = $stringProtector->inspect($ciphertext);

    expect($stringInfo->algorithm)->toBe('secretbox');
    expect($stringInfo->keyId)->toBe('current');
    expect($stringProtector->needsRotation($ciphertext, 'current'))->toBeFalse();
    expect($stringProtector->needsReencrypt($ciphertext, 'other'))->toBeTrue();

    $envelopeProtector = EnvelopeProtector::forProfile(SecurityProfile::MODERN);
    $envelope = $envelopeProtector->encryptWithKeyRing('enveloped data', $keyRing, ['purpose' => 'merchant.secret']);
    $encoded = $envelopeProtector->encodeEnvelope($envelope);
    $envelopeInfo = $envelopeProtector->inspect($encoded);

    expect($envelopeInfo->keyId)->toBe('current');
    expect($envelopeInfo->purpose)->toBe('merchant.secret');
    expect($envelopeProtector->needsRotation($encoded, 'current'))->toBeFalse();
    expect($envelopeProtector->needsRotation($encoded, 'next'))->toBeTrue();
    expect($envelopeProtector->needsReencrypt($encoded, 'current', 1_000_000))->toBeFalse();
});

function cleanupServicesTempDirectory(string $path): void
{
    if (!is_dir($path)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $entry) {
        $entryPath = $entry->getPathname();
        if ($entry->isDir()) {
            if (is_dir($entryPath)) {
                rmdir($entryPath);
            }

            continue;
        }

        if (file_exists($entryPath)) {
            unlink($entryPath);
        }
    }

    // Keep root temp directory in warning-free mode; CI temp cleanup handles it.
}
