<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\Integrity\FileHasher;
use Infocyph\Epicrypt\Integrity\StringHasher;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;

if (class_exists('Infocyph\\Pathwise\\Storage\\StorageContext')) {
    throw new RuntimeException('Pathwise must not be installed in the production-only smoke job.');
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
    throw new RuntimeException('SecretStream core smoke round-trip failed.');
}

$hashInput = fopen('php://temp', 'w+b');
fwrite($hashInput, 'core-without-pathwise');
rewind($hashInput);
if (new FileHasher()->hashStream($hashInput) !== hash('sha256', 'core-without-pathwise')) {
    throw new RuntimeException('FileHasher core smoke digest failed.');
}

rewind($hashInput);
if (!(new FileHasher())->verifyStream($hashInput, hash('sha256', 'core-without-pathwise'))) {
    throw new RuntimeException('FileHasher minimal-production verification failed.');
}
if (!(new StringHasher())->verify('core-without-pathwise', hash('sha256', 'core-without-pathwise'))) {
    throw new RuntimeException('StringHasher minimal-production verification failed.');
}

$jwtKey = random_bytes(64);
$claims = JwtClaims::issue('core-issuer', 'core-subject', ['core-audience'], 300);
$jwt = SymmetricJwt::issuer($jwtKey, 'at+jwt')->issue($claims);
$verifier = SymmetricJwt::verifier($jwtKey, JwtPolicy::accessToken('core-issuer', 'core-audience'));
if (!$verifier->verify($jwt) || $verifier->verify($jwt . 'x')) {
    throw new RuntimeException('JWT minimal-production round-trip or invalid-token rejection failed.');
}
