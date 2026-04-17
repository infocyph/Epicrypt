Complete Usage Reference
========================

This page is an exhaustive usage guide for Epicrypt public capabilities.

Coverage Rules
--------------

- Includes all main public classes under ``Certificate``, ``Crypto``, ``Token``, ``Password``, ``Integrity``, ``Generate``, ``DataProtection``, and ``Security``.
- Includes practical examples for constructors, encode/decode flows, verify flows, key-set flows, and option/context arguments.
- Excludes ``Internal`` and ``Support`` namespace classes because those are implementation details, not stable app-facing API.

Certificate
-----------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\CertificateBuilder;
   use Infocyph\Epicrypt\Certificate\CertificateParser;
   use Infocyph\Epicrypt\Certificate\CsrBuilder;
   use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
   use Infocyph\Epicrypt\Certificate\Enum\KeyPairType;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
   use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
   use Infocyph\Epicrypt\Certificate\KeyExchange;
   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Certificate\OpenSSL\RsaCipher;
   use Infocyph\Epicrypt\Certificate\OpenSSL\DiffieHellman;
   use Infocyph\Epicrypt\Certificate\Sodium\SessionKeyExchange;
   use Infocyph\Epicrypt\Certificate\Sodium\SigningKeyPairGenerator;

   // KeyPairGenerator
   $rsaKeys = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048, OpenSslKeyType::RSA)->generate();
   $ecKeys = KeyPairGenerator::openSsl(
       bits: OpenSslRsaBits::BITS_2048,
       type: OpenSslKeyType::EC,
       curveName: OpenSslCurveName::PRIME256V1,
   )->generate();
   $sodiumBoxKeys = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $sodiumSignKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
   $autoTypeKeys = KeyPairGenerator::forType(KeyPairType::OPENSSL_RSA)->generate();

   // CsrBuilder and CertificateBuilder/Parser
   $dn = [
       'countryName' => 'US',
       'organizationName' => 'Epicrypt',
       'commonName' => 'epicrypt.local',
   ];
   $csr = CsrBuilder::openSsl()->build($dn, $rsaKeys['private']);
   $cert = CertificateBuilder::openSsl('sha512')->selfSign($dn, $rsaKeys['private'], 365);
   $parsed = CertificateParser::openSsl()->parse($cert);

   // KeyExchange
   $exchange = KeyExchange::forBackend(KeyExchangeBackend::SODIUM);
   $secretAB = $exchange->derive($sodiumBoxKeys['private'], KeyPairGenerator::sodium()->generate(asBase64Url: true)['public']);
   $activeBackend = $exchange->backend(); // enum KeyExchangeBackend
   $openSslExchange = KeyExchange::openSsl();
   $sodiumExchange = KeyExchange::sodium();

   // Direct backend usage (advanced)
   $sodiumDirect = new SessionKeyExchange();
   $opensslDirect = new DiffieHellman();
   $directSignKeys = (new SigningKeyPairGenerator())->generate(asBase64Url: true);

   // OpenSSL RSA interoperability
   $rsaCipher = new RsaCipher();
   $encrypted = $rsaCipher->encrypt('interop-message', $rsaKeys['public']);
   $decrypted = $rsaCipher->decrypt($encrypted, $rsaKeys['private']);

Crypto
------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Crypto\AeadCipher;
   use Infocyph\Epicrypt\Crypto\BinaryCodec;
   use Infocyph\Epicrypt\Crypto\Enum\AeadAlgorithm;
   use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
   use Infocyph\Epicrypt\Crypto\Mac;
   use Infocyph\Epicrypt\Crypto\PublicKeyBoxCipher;
   use Infocyph\Epicrypt\Crypto\SealedBoxCipher;
   use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
   use Infocyph\Epicrypt\Crypto\SecretStream;
   use Infocyph\Epicrypt\Crypto\Signature;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   // AeadCipher with context options: aad, key_is_binary, nonce, nonce_is_binary
   $aeadKey = (new KeyMaterialGenerator())->generate(
       AeadAlgorithm::XCHACHA20_POLY1305_IETF->keyLength(),
   );
   $aead = new AeadCipher(AeadAlgorithm::XCHACHA20_POLY1305_IETF);
   $aeadCiphertext = $aead->encrypt('aead-message', $aeadKey, ['aad' => 'meta']);
   $aeadPlain = $aead->decrypt($aeadCiphertext, $aeadKey, ['aad' => 'meta']);

   // SecretBoxCipher (context option: key_is_binary)
   $secretBoxKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
   $secretBox = new SecretBoxCipher();
   $secretBoxCiphertext = $secretBox->encrypt('secretbox-message', $secretBoxKey);
   $secretBoxPlain = $secretBox->decrypt($secretBoxCiphertext, $secretBoxKey);

   // PublicKeyBoxCipher (keys are arrays + optional key_is_binary context)
   $sender = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $recipient = KeyPairGenerator::sodium()->generate(asBase64Url: true);
   $publicBox = new PublicKeyBoxCipher();
   $publicBoxCiphertext = $publicBox->encrypt('public-box-message', [
       'recipient_public' => $recipient['public'],
       'sender_private' => $sender['private'],
   ]);
   $publicBoxPlain = $publicBox->decrypt($publicBoxCiphertext, [
       'sender_public' => $sender['public'],
       'recipient_private' => $recipient['private'],
   ]);

   // SealedBoxCipher
   $keypair = sodium_crypto_box_keypair();
   $public = sodium_bin2base64(sodium_crypto_box_publickey($keypair), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
   $pair = sodium_bin2base64($keypair, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
   $sealed = new SealedBoxCipher();
   $sealedCiphertext = $sealed->encrypt('sealed-box-message', $public);
   $sealedPlain = $sealed->decrypt($sealedCiphertext, $pair);

   // Signature (context option: key_is_binary)
   $signKeys = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
   $signatureService = new Signature();
   $signature = $signatureService->sign('sign-me', $signKeys['private']);
   $signatureValid = $signatureService->verify('sign-me', $signature, $signKeys['public']);

   // MAC (context option: key_is_binary)
   $mac = new Mac();
   $macKey = $mac->generateKey();
   $tag = $mac->generate('mac-message', $macKey);
   $tagValid = $mac->verify('mac-message', $tag, $macKey);

   // SecretStream for chunked file encryption/decryption
   $streamKey = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
   $stream = new SecretStream($streamKey, StreamAlgorithm::XCHACHA20POLY1305, 'aad');
   $lastChunkSize = $stream->encrypt('/tmp/plain.bin', '/tmp/plain.bin.epc', 8192);
   $stream->decrypt('/tmp/plain.bin.epc', '/tmp/plain.dec.bin', 8192);

   // BinaryCodec
   $codec = new BinaryCodec();
   $encoded = $codec->encode(random_bytes(32));
   $decoded = $codec->decode($encoded);

Token
-----

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
   use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
   use Infocyph\Epicrypt\Token\Jwt\KeyResolver;
   use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
   use Infocyph\Epicrypt\Token\Jwt\Validation\ClaimValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\AudienceValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\ExpirationValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\IssuerValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidator;
   use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
   use Infocyph\Epicrypt\Token\Jwt\Validation\SubjectValidator;
   use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;
   use Infocyph\Epicrypt\Token\Payload\SignedPayload;

   $now = time();
   $claims = [
       'iss' => 'issuer-service',
       'aud' => 'audience-service',
       'sub' => 'subject-service',
       'jti' => 'token-1',
       'nbf' => $now,
       'exp' => $now + 600,
       'scope' => 'admin',
       'kid' => 'k2',
   ];

   // Symmetric JWT with key-set mode (kid required when key is array/ArrayAccess)
   $symKeys = ['k1' => 'legacy-secret', 'k2' => 'active-secret'];
   $sym = new SymmetricJwt(SymmetricJwtAlgorithm::HS512);
   $symToken = $sym->encode($claims, $symKeys);
   $symVerifier = new SymmetricJwt(
       SymmetricJwtAlgorithm::HS512,
       new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-1'),
   );
   $symPayload = $symVerifier->decode($symToken, $symKeys);
   $symValid = $symVerifier->verify($symToken, $symKeys);

   // Asymmetric JWT with kid + key-set
   $rsaA = KeyPairGenerator::openSsl()->generate();
   $rsaB = KeyPairGenerator::openSsl()->generate();
   $privateSet = ['k1' => $rsaA['private'], 'k2' => $rsaB['private']];
   $publicSet = ['k1' => $rsaA['public'], 'k2' => $rsaB['public']];
   $asym = new AsymmetricJwt(null, AsymmetricJwtAlgorithm::RS512);
   $asymToken = $asym->encode($claims, $privateSet);
   $asymVerifier = new AsymmetricJwt(
       null,
       AsymmetricJwtAlgorithm::RS512,
       new RegisteredClaims('issuer-service', 'audience-service', 'subject-service', 'token-1'),
   );
   $asymPayload = $asymVerifier->decode($asymToken, $publicSet);
   $asymValid = $asymVerifier->verify($asymToken, $publicSet);

   // SignedPayload
   $signedPayload = new SignedPayload('reset_password');
   $payloadToken = $signedPayload->encode(['sub' => 'user-1', 'purpose' => 'reset'], 'payload-secret', ['exp' => time() + 600]);
   $payloadClaims = $signedPayload->decode($payloadToken, 'payload-secret');
   $payloadValid = $signedPayload->verify($payloadToken, 'payload-secret');

   // OpaqueToken
   $opaque = new OpaqueToken();
   $opaqueToken = $opaque->issue(48);
   $opaqueDigest = $opaque->hash($opaqueToken);
   $opaqueValid = $opaque->verify($opaqueToken, $opaqueDigest);

   // KeyResolver utilities
   KeyResolver::validate($symKeys, 'k2');
   $resolved = KeyResolver::resolve($symKeys, 'k2');

   // Claim validators
   $claimValidator = new ClaimValidator();
   $claimValidator->assertRequired($claims, ['iss', 'aud', 'sub', 'nbf', 'exp']);
   $claimValidator->assertStringClaim($claims, 'iss');

   $registered = RegisteredClaims::fromArray($claims);
   (new JwtValidator($registered))->validate($claims);
   (new IssuerValidator())->validate('issuer-service', $claims['iss']);
   (new AudienceValidator())->validate('audience-service', $claims['aud']);
   (new SubjectValidator())->validate('subject-service', $claims['sub']);
   (new ExpirationValidator())->validate($claims['nbf'], $claims['exp']);

Password
--------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
   use Infocyph\Epicrypt\Password\Generator\PasswordGenerator;
   use Infocyph\Epicrypt\Password\Generator\PasswordPolicy;
   use Infocyph\Epicrypt\Password\PasswordHasher;
   use Infocyph\Epicrypt\Password\PasswordStrength;
   use Infocyph\Epicrypt\Password\Secret\MasterSecretGenerator;
   use Infocyph\Epicrypt\Password\Secret\SecureSecretSerializer;
   use Infocyph\Epicrypt\Password\Secret\WrappedSecretManager;

   // PasswordGenerator options
   $password = (new PasswordGenerator())->generate(20, [
       'min_length' => 16,
       'require_upper' => true,
       'require_lower' => true,
       'require_digit' => true,
       'require_symbol' => true,
       'include_ambiguous' => false,
   ]);

   // PasswordPolicy value object
   $policy = new PasswordPolicy(minLength: 12, requireUpper: true, requireLower: true, requireDigit: true, requireSymbol: true);

   // PasswordHasher
   $hasher = new PasswordHasher();
   $hash = $hasher->hashPassword($password, [
       'algorithm' => PasswordHashAlgorithm::ARGON2ID,
       'memory_cost' => 65536,
       'time_cost' => 4,
       'threads' => 2,
   ]);
   $passwordValid = $hasher->verifyPassword($password, $hash);

   // PasswordStrength
   $score = (new PasswordStrength())->score($password); // 0..100

   // Secret helpers
   $masterSecret = (new MasterSecretGenerator())->generate(32, true);
   $wrappedManager = new WrappedSecretManager();
   $wrapped = $wrappedManager->wrap('db-password', $masterSecret);
   $plain = $wrappedManager->unwrap($wrapped, $masterSecret);

   $serializer = new SecureSecretSerializer();
   $serialized = $serializer->serialize(['username' => 'alice', 'password' => 'db-password']);
   $restored = $serializer->unserialize($serialized);

Integrity
---------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integrity\FileHasher;
   use Infocyph\Epicrypt\Integrity\StringHasher;
   use Infocyph\Epicrypt\Integrity\Support\ContentFingerprinter;
   use Infocyph\Epicrypt\Integrity\Support\TimingSafeComparator;

   // StringHasher
   $stringHasher = new StringHasher('sha256');
   $digest = $stringHasher->hash('payload');
   $digestValid = $stringHasher->verify('payload', $digest);

   // StringHasher with HMAC
   $hmac = $stringHasher->hash('payload', ['key' => 'shared-secret']);

   // StringHasher with Blake2b
   $blake = (new StringHasher('blake2b'))->hash('payload', ['length' => 32]);

   // FileHasher
   $fileHasher = new FileHasher('sha256');
   $fileDigest = $fileHasher->hash('/tmp/payload.txt');
   $fileDigestValid = $fileHasher->verify('/tmp/payload.txt', $fileDigest);

   // FileHasher with keyed hashing
   $fileHmac = $fileHasher->hash('/tmp/payload.txt', 'shared-secret');

   // Support helpers
   $fingerprint = (new ContentFingerprinter())->fingerprint('payload', ['a' => '1', 'b' => '2']);
   $same = (new TimingSafeComparator())->equals('known', 'known');

Generate
--------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
   use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;
   use Infocyph\Epicrypt\Generate\NonceGenerator;
   use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
   use Infocyph\Epicrypt\Generate\SaltGenerator;

   $random = new RandomBytesGenerator();
   $rawBytes = $random->bytes(32);
   $randomString = $random->string(48, 'tok_', '_v1');

   $nonce = (new NonceGenerator())->generate(24, true);
   $salt = (new SaltGenerator())->generate(16, true);
   $keyMaterial = (new KeyMaterialGenerator())->generate(32, true);
   $tokenMaterial = (new TokenMaterialGenerator())->generate(48);

Data Protection
---------------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\DataProtection\OpenSSL\InteroperabilityCryptoHelper;
   use Infocyph\Epicrypt\DataProtection\StringProtector;
   use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;

   $key = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

   // StringProtector
   $stringProtector = new StringProtector();
   $ciphertext = $stringProtector->encrypt('sensitive data', $key);
   $plaintext = $stringProtector->decrypt($ciphertext, $key);

   // EnvelopeProtector
   $envelopeProtector = new EnvelopeProtector();
   $envelope = $envelopeProtector->encrypt('payload', $key);
   $encodedEnvelope = $envelopeProtector->encodeEnvelope($envelope);
   $decoded = $envelopeProtector->decrypt($encodedEnvelope, $key);

   // FileProtector
   $fileKey = (new KeyMaterialGenerator())->generate(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
   $fileProtector = new FileProtector();
   $lastChunk = $fileProtector->encrypt('/tmp/in.bin', '/tmp/in.bin.epc', $fileKey, 8192, false);
   $fileProtector->decrypt('/tmp/in.bin.epc', '/tmp/in.dec.bin', $fileKey, 8192, false);

   // OpenSSL interoperability helper
   $interop = new InteroperabilityCryptoHelper();
   $interopCipher = $interop->encryptString('legacy-payload', 'app-secret', 'salt-value', true);
   $interopPlain = $interop->decryptString($interopCipher, 'app-secret', 'salt-value', true);

Security
--------

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Security\ActionToken;
   use Infocyph\Epicrypt\Security\CsrfTokenManager;
   use Infocyph\Epicrypt\Security\EmailVerificationToken;
   use Infocyph\Epicrypt\Security\KeyRotationHelper;
   use Infocyph\Epicrypt\Security\PasswordResetToken;
   use Infocyph\Epicrypt\Security\RememberToken;
   use Infocyph\Epicrypt\Security\SignedUrl;
   use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;

   // SignedUrl
   $signedUrl = new SignedUrl('url-secret');
   $link = $signedUrl->generate('https://example.com/download', ['file' => 'report.csv'], time() + 300);
   $linkValid = $signedUrl->verify($link);

   // CsrfTokenManager
   $csrf = new CsrfTokenManager('csrf-secret', 3600);
   $csrfToken = $csrf->issueToken('session-123');
   $csrfValid = $csrf->verifyToken('session-123', $csrfToken);

   // Purpose-bound tokens
   $reset = new PasswordResetToken('token-secret', 1800);
   $resetToken = $reset->issue('user-1');
   $resetValid = $reset->verify($resetToken, 'user-1');

   $email = new EmailVerificationToken('token-secret', 86400);
   $emailToken = $email->issue('user-1', 'user@example.com');
   $emailValid = $email->verify($emailToken, 'user@example.com');

   $remember = new RememberToken('token-secret', 1209600);
   $rememberToken = $remember->issue('user-1', 'device-1');
   $rememberValid = $remember->verify($rememberToken, 'user-1', 'device-1');

   $action = new ActionToken('token-secret', 900);
   $actionToken = $action->issue('user-1', 'delete-account', ['ip' => '203.0.113.10']);
   $actionValid = $action->verify($actionToken, 'user-1', 'delete-account');
   $csrfPurpose = SecurityTokenPurpose::CSRF->value;

   // KeyRotationHelper
   $rotation = new KeyRotationHelper();
   $keys = ['k1' => 'legacy-key', 'k2' => 'active-key'];
   $signature = $rotation->sign('payload', 'k2', $keys);
   $validWithKid = $rotation->verify('payload', $signature, $keys, 'k2');
   $validAgainstWholeSet = $rotation->verify('payload', $signature, $keys);
