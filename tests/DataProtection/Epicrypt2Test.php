<?php

declare(strict_types=1);

use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionAlgorithm;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;

it('authenticates Epicrypt 2.0 string and envelope metadata', function () {
    $key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $options = new ProtectionOptions('customer-record', 'tenant=7', 'primary');

    foreach ([new StringProtector(), new EnvelopeProtector()] as $protector) {
        $payload = $protector->protect('sensitive value', $key, $options);
        expect($payload)->toStartWith('ep2.')
            ->and($protector->unprotect($payload, $key, $options))->toBe('sensitive value');

        expect(fn() => $protector->unprotect($payload, $key, new ProtectionOptions('other', 'tenant=7', 'primary')))
            ->toThrow(DecryptionException::class)
            ->and(fn() => $protector->unprotect($payload, $key, new ProtectionOptions('customer-record', 'tenant=8', 'primary')))
            ->toThrow(DecryptionException::class);

        $parts = explode('.', $payload);
        $parts[1][3] = $parts[1][3] === 'A' ? 'B' : 'A';
        expect(fn() => $protector->unprotect(implode('.', $parts), $key, $options))
            ->toThrow(DecryptionException::class);
    }
});

it('supports each available approved AEAD with XChaCha20-Poly1305 as the default', function () {
    $defaultOptions = new ProtectionOptions('default');
    $defaultKey = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $defaultPayload = StringProtector::create()->protect('value', $defaultKey, $defaultOptions);
    $defaultHeader = json_decode(
        sodium_base642bin(explode('.', $defaultPayload)[1], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
        true,
        flags: JSON_THROW_ON_ERROR,
    );
    expect($defaultHeader['alg'])->toBe(ProtectionAlgorithm::XCHACHA20_POLY1305->value);

    $algorithms = array_values(array_filter(
        ProtectionAlgorithm::cases(),
        static fn(ProtectionAlgorithm $algorithm): bool => $algorithm->isAvailable(),
    ));

    foreach ($algorithms as $algorithm) {
        $key = sodium_bin2base64(
            random_bytes($algorithm->keyLength()),
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
        );
        $options = new ProtectionOptions('algorithm-matrix');

        foreach ([StringProtector::create($algorithm), EnvelopeProtector::create($algorithm)] as $protector) {
            $payload = $protector->protect('protected value', $key, $options);
            $encodedHeader = explode('.', $payload)[1];
            $header = json_decode(
                sodium_base642bin($encodedHeader, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
                true,
                flags: JSON_THROW_ON_ERROR,
            );

            expect($header['alg'])->toBe($algorithm->value)
                ->and($protector->unprotect($payload, $key, $options))->toBe('protected value');

            foreach ($algorithms as $otherAlgorithm) {
                if ($otherAlgorithm !== $algorithm) {
                    $mismatchedProtector = $protector instanceof StringProtector
                        ? StringProtector::create($otherAlgorithm)
                        : EnvelopeProtector::create($otherAlgorithm);
                    expect(fn() => $mismatchedProtector->unprotect(
                        $payload,
                        $key,
                        $options,
                    ))->toThrow(DecryptionException::class);

                    break;
                }
            }
        }
    }
});

it('enforces KeyRing policy for data protection', function () {
    $active = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $fallback = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $ring = new KeyRing([
        new KeyRingEntry('current', $active, KeyStatus::ACTIVE, KeyPurpose::DATA_PROTECTION, 'xchacha20-poly1305-ietf'),
        new KeyRingEntry('previous', $fallback, KeyStatus::FALLBACK, KeyPurpose::DATA_PROTECTION, 'xchacha20-poly1305-ietf'),
        new KeyRingEntry('disabled', $fallback, KeyStatus::DISABLED, KeyPurpose::DATA_PROTECTION, 'xchacha20-poly1305-ietf'),
    ]);
    $protector = new StringProtector();
    $options = new ProtectionOptions('session');
    $payload = $protector->protectWithKeyRing('value', $ring, $options);

    expect($protector->unprotectWithKeyRing($payload, $ring, $options)->value)->toBe('value')
        ->and($ring->resolveForRead('disabled', KeyPurpose::DATA_PROTECTION, 'xchacha20-poly1305-ietf'))->toBeNull()
        ->and($ring->resolveForRead('current', KeyPurpose::FILE_PROTECTION, 'xchacha20-poly1305-ietf'))->toBeNull();
});

it('rejects malformed framing, corrupt content, invalid keys, and mismatched key ids', function () {
    foreach (ProtectionAlgorithm::cases() as $algorithm) {
        if (!$algorithm->isAvailable()) {
            continue;
        }

        $protector = StringProtector::create($algorithm);
        $key = random_bytes($algorithm->keyLength());
        $options = new ProtectionOptions('records', 'tenant=9', 'expected');
        $payload = $protector->protectWithBinaryKey('value', $key, $options);
        $parts = explode('.', $payload);
        $parts[3][0] = $parts[3][0] === 'A' ? 'B' : 'A';

        expect(fn() => $protector->protectWithBinaryKey('value', substr($key, 1), $options))
            ->toThrow(\Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException::class)
            ->and(fn() => $protector->unprotectWithBinaryKey(implode('.', $parts), $key, $options))
            ->toThrow(DecryptionException::class)
            ->and(fn() => $protector->unprotectWithBinaryKey('ep2.invalid', $key, $options))
            ->toThrow(DecryptionException::class)
            ->and(fn() => $protector->unprotectWithBinaryKey(
                $payload,
                $key,
                new ProtectionOptions('records', 'tenant=9', 'wrong'),
            ))->toThrow(DecryptionException::class);
    }
});

it('roundtrips a property corpus across supported protection algorithms', function () {
    foreach (ProtectionAlgorithm::cases() as $algorithm) {
        if (!$algorithm->isAvailable()) {
            continue;
        }

        $protector = StringProtector::create($algorithm);
        $key = random_bytes($algorithm->keyLength());
        foreach ([0, 1, 15, 16, 17, 255, 256, 257, 4096] as $length) {
            $plaintext = substr(str_repeat(hash('sha512', (string) $length, true), 65), 0, $length);
            $options = new ProtectionOptions('property-' . $length, pack('N', $length));
            $payload = $protector->protectWithBinaryKey($plaintext, $key, $options);

            expect($protector->unprotectWithBinaryKey($payload, $key, $options))->toBe($plaintext);
        }
    }
});

it('decrypts the stable Epicrypt 2.0 XChaCha fixture', function () {
    $fixture = 'ep2.eyJ2IjoyLCJkb21haW4iOiJzdHJpbmciLCJhbGciOiJ4Y2hhY2hhMjAtcG9seTEzMDUtaWV0ZiIsImtpZCI6ImZpeHR1cmUta2V5IiwicHVycG9zZSI6ImZpeHR1cmUiLCJjcmVhdGVkX2F0IjoxNzAwMDAwMDAwLCJhYWQiOiJkR1Z1WVc1MFBXWnBlSFIxY21VIn0.-uWGl1cvzGxHY7cRu0J4_No4F9CwAY3t.Tj-OsINuflTjjImnhNO5ErVO4dqr5jHNrL_wo8cLkggbKiFL';
    $options = new ProtectionOptions('fixture', 'tenant=fixture', 'fixture-key');
    $result = StringProtector::create()->unprotectWithBinaryKeyResult($fixture, str_repeat('K', 32), $options);

    expect($result->value)->toBe('Epicrypt 2.0 fixture')
        ->and($result->createdAt)->toBe(1_700_000_000)
        ->and($result->keyId)->toBe('fixture-key');
});
