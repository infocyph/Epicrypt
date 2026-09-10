<?php

declare(strict_types=1);

use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Pathwise\Storage\StorageContext;

it('interoperates with independent Pathwise 4 storage contexts through explicit streams', function () {
    $base = sys_get_temp_dir() . '/epicrypt-pathwise4-' . bin2hex(random_bytes(6));
    $rootA = $base . '/a';
    $rootB = $base . '/b';
    mkdir($rootA, 0700, true);
    mkdir($rootB, 0700, true);

    $contextA = new StorageContext(['shared' => ['driver' => 'local', 'root' => $rootA]], 'shared');
    $contextB = new StorageContext(['shared' => ['driver' => 'local', 'root' => $rootB]], 'shared');
    $contextA->filesystem()->write('plain.txt', 'context-a');
    $contextB->filesystem()->write('plain.txt', 'context-b');

    $key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $protector = new FileProtector();
    $options = new ProtectionOptions('pathwise4-interop');

    foreach ([[$contextA, 'context-a'], [$contextB, 'context-b']] as [$context, $expected]) {
        $input = $context->filesystem()->readStream('plain.txt');
        $encrypted = fopen('php://temp', 'w+b');
        $protector->protectStream($input, $encrypted, $key, $options, 1024);
        fclose($input);

        rewind($encrypted);
        $context->filesystem()->writeStream('protected.ep2', $encrypted);
        fclose($encrypted);

        $protected = $context->filesystem()->readStream('protected.ep2');
        $output = fopen('php://temp', 'w+b');
        $protector->unprotectStream($protected, $output, $key, $options, 1024);
        fclose($protected);
        rewind($output);

        expect(stream_get_contents($output))->toBe($expected);
        fclose($output);
    }

    expect($contextA->filesystem()->read('plain.txt'))->toBe('context-a')
        ->and($contextB->filesystem()->read('plain.txt'))->toBe('context-b');
});
