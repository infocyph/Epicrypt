<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\SigningKeyReadinessException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use phpseclib4\Crypt\PublicKeyLoader;
use Throwable;

final readonly class AsymmetricSigningKeySet
{
    private const int MAX_ISSUER_BYTES = 2048;

    private KeyMetadata $activeMetadata;

    /** @var array{keys: list<array<string, mixed>>} */
    private array $jwks;

    public function __construct(
        public string $issuer,
        public string $activeKeyId,
        #[\SensitiveParameter]
        private string $privateKey,
        #[\SensitiveParameter]
        private KeyRing $publicKeys,
        public AsymmetricJwtAlgorithm $algorithm,
        #[\SensitiveParameter]
        private ?string $privateKeyPassphrase = null,
        public KeyPurpose $purpose = KeyPurpose::JWT_SIGNING,
    ) {
        $issuerLength = strlen($this->issuer);
        if ($issuerLength < 1
            || $issuerLength > self::MAX_ISSUER_BYTES
            || preg_match('/[\x00-\x1F\x7F]/', $this->issuer) === 1) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::INVALID_ISSUER);
        }
        if (preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $this->activeKeyId) !== 1) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::INVALID_KEY_ID);
        }

        try {
            $active = $this->publicKeys->activeForWrite(
                $this->purpose,
                $this->algorithm->value,
                $this->issuer,
            );
        } catch (Throwable) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::ACTIVE_KEY_NOT_ELIGIBLE);
        }
        if (!hash_equals($this->activeKeyId, $active->id)) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::ACTIVE_KEY_ID_MISMATCH);
        }

        if ($this->algorithm->isEdDsa()) {
            $this->assertEdDsaPair($active);
        } else {
            $this->assertPemPair($active);
        }

        $this->activeMetadata = $active->metadata();
        $this->jwks = $this->exportJwks();
    }

    public function activeMetadata(): KeyMetadata
    {
        return $this->activeMetadata;
    }

    /** @return array{keys: list<array<string, mixed>>} */
    public function jwks(): array
    {
        return $this->jwks;
    }

    public function privateKey(): string
    {
        return $this->privateKey;
    }

    public function privateKeyPassphrase(): ?string
    {
        return $this->privateKeyPassphrase;
    }

    public function publicKeys(): KeyRing
    {
        return $this->publicKeys;
    }

    private function assertEdDsaPair(KeyRingEntry $active): void
    {
        if ($this->privateKeyPassphrase !== null && $this->privateKeyPassphrase !== '') {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::PRIVATE_KEY_INVALID);
        }
        if (strlen($this->privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::PRIVATE_KEY_INVALID);
        }

        try {
            new Jwks()->exportOkpPublicKey(
                $active->key,
                $active->id,
                $this->algorithm->value,
                'Ed25519',
            );
        } catch (Throwable) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::PUBLIC_KEY_SET_INVALID);
        }

        $derived = sodium_crypto_sign_publickey_from_secretkey($this->privateKey);
        if (!hash_equals($active->key, $derived)) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::KEY_PAIR_MISMATCH);
        }
    }

    private function assertPemPair(KeyRingEntry $active): void
    {
        $jwks = new Jwks();

        try {
            $activeJwk = $jwks->exportPublicKeyToJwk($active->key, $active->id, $this->algorithm);
        } catch (Throwable) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::PUBLIC_KEY_SET_INVALID);
        }

        try {
            $private = PublicKeyLoader::loadPrivateKey($this->privateKey, $this->privateKeyPassphrase);
            $derivedPublic = $private->getPublicKey()->toString('PKCS8');
            $derivedJwk = $jwks->exportPublicKeyToJwk($derivedPublic, $active->id, $this->algorithm);
        } catch (Throwable) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::PRIVATE_KEY_INVALID);
        }

        try {
            $matches = hash_equals($jwks->thumbprint($activeJwk), $jwks->thumbprint($derivedJwk));
        } catch (Throwable) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::PUBLIC_KEY_SET_INVALID);
        }
        if (!$matches) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::KEY_PAIR_MISMATCH);
        }
    }

    /** @return array{keys: list<array<string, mixed>>} */
    private function exportJwks(): array
    {
        $jwks = new Jwks();
        $keys = [];

        try {
            foreach ($this->publicKeys->readCandidates(
                $this->purpose,
                $this->algorithm->value,
                $this->issuer,
            ) as $entry) {
                $keys[] = $this->algorithm->isEdDsa()
                    ? $jwks->exportOkpPublicKey(
                        $entry->key,
                        $entry->id,
                        $this->algorithm->value,
                        'Ed25519',
                    )
                    : $jwks->exportPublicKeyToJwk($entry->key, $entry->id, $this->algorithm);
            }

            return ['keys' => $keys];
        } catch (SigningKeyReadinessException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new SigningKeyReadinessException(SigningKeyReadinessFailureReason::PUBLIC_KEY_SET_INVALID);
        }
    }
}
