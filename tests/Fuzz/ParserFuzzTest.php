<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\DataProtection\StringProtector;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\EcdsaSignatureConverter;
use Infocyph\Epicrypt\Security\SignedUrl;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwe;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\Jws;

/** @param Closure(): mixed $operation */
function runFuzzBoundary(Closure $operation): void
{
    try {
        $operation();
    } catch (Error $error) {
        throw $error;
    } catch (Throwable) {
        // A typed/domain rejection is the expected result for malformed input.
    }
}

it('rejects a deterministic cross-capability parser fuzz corpus without crashes or hangs', function () {
    $aead = new AeadCipher();
    $aeadKey = Base64Url::encode(random_bytes(32));
    $protectionKey = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $jws = Jws::verifier(random_bytes(32), SymmetricJwtAlgorithm::HS256);
    $jwe = new Jwe(random_bytes(32));
    $signedUrl = new SignedUrl(str_repeat('f', 32));
    $corpus = [
        '', '.', '..', '...', '....',
        '%', '%0', '%GG', "\0", "\xFF",
        '{', '[', ']', '}', '{"a":1,"a":2}',
        '{"a":"\\uD800"}', '{"a":1e999999}',
        str_repeat('[', 40).str_repeat(']', 40),
        str_repeat('A', 16_385),
        'a=b&a=c', 'a.b=c', 'a[0][1]=c',
    ];

    foreach ($corpus as $input) {
        runFuzzBoundary(fn () => $aead->decrypt($input, $aeadKey));
        runFuzzBoundary(fn () => StringProtector::create()->unprotect(
            $input,
            $protectionKey,
            new ProtectionOptions('fuzz/v1'),
        ));
        runFuzzBoundary(fn () => $jws->verifyCompact($input));
        runFuzzBoundary(fn () => $jws->verifyFlattened($input));
        runFuzzBoundary(fn () => $jwe->decryptCompact($input));
        runFuzzBoundary(fn () => $jwe->decryptFlattened($input));
        runFuzzBoundary(fn () => new Jwks()->importPublicKeyFromJwk(
            ['kty' => $input, 'kid' => 'fuzz', 'alg' => 'RS256'],
            AsymmetricJwtAlgorithm::RS256,
        ));
        runFuzzBoundary(fn () => $signedUrl->verify('https://example.test/path?'.$input));
        runFuzzBoundary(fn () => Base64Url::decode($input));
        runFuzzBoundary(fn () => new EcdsaSignatureConverter()->fromAsn1($input, 64));
    }

    expect(true)->toBeTrue();
});
