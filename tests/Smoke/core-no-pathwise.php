<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\Integrity\FileHasher;

if (class_exists('Infocyph\\Pathwise\\Storage\\StorageContext')) {
    fwrite(STDERR, "Pathwise must not be installed in the production-only smoke job.\n");
    exit(1);
}

$key = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
$input = fopen('php://temp', 'w+b');
$encrypted = fopen('php://temp', 'w+b');
$output = fopen('php://temp', 'w+b');
fwrite($input, 'core-without-pathwise');
rewind($input);

$stream = new SecretStream($key);
$stream->encryptStream($input, $encrypted, 1024);
rewind($encrypted);
$stream->decryptStream($encrypted, $output, 1024);
rewind($output);
if (stream_get_contents($output) !== 'core-without-pathwise') {
    exit(2);
}

$hashInput = fopen('php://temp', 'w+b');
fwrite($hashInput, 'core-without-pathwise');
rewind($hashInput);
if (new FileHasher()->hashStream($hashInput) !== hash('sha256', 'core-without-pathwise')) {
    exit(3);
}
