<?php

declare(strict_types=1);

use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;

/** @return string */
function filePublicationSafetyDirectory(): string
{
    $directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'epicrypt-file-publication-' . bin2hex(random_bytes(8));
    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create file-publication test directory.');
    }

    return $directory;
}

function removeFilePublicationSafetyDirectory(string $directory): void
{
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $path) {
        if (is_file($path) || is_link($path)) {
            unlink($path);
        }
    }

    if (is_dir($directory)) {
        rmdir($directory);
    }
}

it('publishes local protected and unprotected outputs with restrictive permissions', function () {
    if (PHP_OS_FAMILY === 'Windows') {
        $this->markTestSkipped('POSIX permission bits are not authoritative on Windows.');
    }

    $directory = filePublicationSafetyDirectory();

    try {
        $plaintext = $directory . DIRECTORY_SEPARATOR . 'application.env';
        $protected = $directory . DIRECTORY_SEPARATOR . 'application.env.encrypted';
        $restored = $directory . DIRECTORY_SEPARATOR . 'application.env.restored';
        file_put_contents($plaintext, "APP_ENV=production\nSECRET=value\n");

        $key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $options = new ProtectionOptions('environment-file', 'environment-file/v1');
        $protector = new FileProtector();

        $protector->protect($plaintext, $protected, $key, $options);
        $protector->unprotect($protected, $restored, $key, $options);

        clearstatcache(true, $protected);
        clearstatcache(true, $restored);

        expect(fileperms($protected) & 0777)->toBe(0600)
            ->and(fileperms($restored) & 0777)->toBe(0600)
            ->and(file_get_contents($restored))->toBe("APP_ENV=production\nSECRET=value\n")
            ->and(glob($directory . DIRECTORY_SEPARATOR . '.epicrypt-*') ?: [])->toBe([]);
    } finally {
        removeFilePublicationSafetyDirectory($directory);
    }
});

it('preserves an existing destination and removes staging files after failed decryption', function () {
    $directory = filePublicationSafetyDirectory();

    try {
        $plaintext = $directory . DIRECTORY_SEPARATOR . 'source.env';
        $protected = $directory . DIRECTORY_SEPARATOR . 'source.env.encrypted';
        $target = $directory . DIRECTORY_SEPARATOR . 'target.env';
        file_put_contents($plaintext, "SECRET=new-value\n");
        file_put_contents($target, "SECRET=previous-value\n");

        $key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $wrongKey = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $options = new ProtectionOptions('environment-file', 'environment-file/v1');
        $protector = new FileProtector();
        $protector->protect($plaintext, $protected, $key, $options);

        expect(fn () => $protector->unprotect($protected, $target, $wrongKey, $options))
            ->toThrow(DecryptionException::class)
            ->and(file_get_contents($target))->toBe("SECRET=previous-value\n")
            ->and(glob($directory . DIRECTORY_SEPARATOR . '.epicrypt-*') ?: [])->toBe([]);
    } finally {
        removeFilePublicationSafetyDirectory($directory);
    }
});

it('preserves an existing destination and removes staging files after failed protection', function () {
    $directory = filePublicationSafetyDirectory();

    try {
        $plaintext = $directory . DIRECTORY_SEPARATOR . 'source.env';
        $target = $directory . DIRECTORY_SEPARATOR . 'target.env.encrypted';
        file_put_contents($plaintext, "SECRET=new-value\n");
        file_put_contents($target, 'previous-protected-value');

        $options = new ProtectionOptions('environment-file', 'environment-file/v1');
        $protector = new FileProtector();
        $invalidKey = sodium_bin2base64(random_bytes(31), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

        expect(fn () => $protector->protect($plaintext, $target, $invalidKey, $options))
            ->toThrow(InvalidKeyException::class)
            ->and(file_get_contents($target))->toBe('previous-protected-value')
            ->and(glob($directory . DIRECTORY_SEPARATOR . '.epicrypt-*') ?: [])->toBe([]);
    } finally {
        removeFilePublicationSafetyDirectory($directory);
    }
});
