<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweContentEncryptionAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JweContentCipher;
use Infocyph\Epicrypt\Token\Jwt\Support\JweKeyManager;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;

final readonly class Jwe
{
    private const int MAX_CIPHERTEXT_BYTES = 16_777_216;

    public function __construct(
        #[\SensitiveParameter]
        private string $key,
        private JweKeyManagementAlgorithm $algorithm = JweKeyManagementAlgorithm::DIRECT,
        private JweContentEncryptionAlgorithm $contentEncryption = JweContentEncryptionAlgorithm::A256GCM,
        private ?string $keyId = null,
    ) {
        if ($key === '' || ($keyId !== null && preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $keyId) !== 1)) {
            throw new InvalidTokenException('JWE key and kid configuration is invalid.');
        }
    }

    public function decryptCompact(#[\SensitiveParameter] string $token): string
    {
        if (strlen($token) > self::MAX_CIPHERTEXT_BYTES) {
            throw new InvalidTokenException('JWE compact serialization exceeds its size bound.');
        }
        $parts = explode('.', $token);
        if (count($parts) !== 5 || $parts[0] === '' || $parts[2] === '' || $parts[3] === '' || $parts[4] === '') {
            throw new InvalidTokenException('JWE compact serialization must contain five valid segments.');
        }
        [$encodedHeader, $encryptedKey, $iv, $ciphertext, $tag] = $parts;
        $header = $this->decodeProtected($encodedHeader);
        $this->validateProtected($header);
        $cek = new JweKeyManager()->unwrap($this->algorithm, $this->key, $this->decodeEncryptedKey($encryptedKey), $header);

        return new JweContentCipher()->decrypt(
            $this->decodeSegment($ciphertext, 'ciphertext'),
            $cek,
            $encodedHeader,
            $this->decodeSegment($iv, 'iv'),
            $this->decodeSegment($tag, 'tag'),
        );
    }

    public function decryptFlattened(#[\SensitiveParameter] string $token): string
    {
        $document = $this->decodeDocument($token);
        foreach (['protected', 'iv', 'ciphertext', 'tag'] as $name) {
            if (!is_string($document[$name] ?? null)) {
                throw new InvalidTokenException(sprintf('Flattened JWE requires string %s.', $name));
            }
        }
        if (isset($document['encrypted_key']) && !is_string($document['encrypted_key'])) {
            throw new InvalidTokenException('Flattened JWE encrypted_key must be a string when present.');
        }
        $header = $this->decodeProtected($document['protected']);
        $this->validateProtected($header);
        $cek = new JweKeyManager()->unwrap(
            $this->algorithm,
            $this->key,
            $this->decodeEncryptedKey($document['encrypted_key'] ?? ''),
            $header,
        );

        return new JweContentCipher()->decrypt(
            $this->decodeSegment($document['ciphertext'], 'ciphertext'),
            $cek,
            $document['protected'],
            $this->decodeSegment($document['iv'], 'iv'),
            $this->decodeSegment($document['tag'], 'tag'),
        );
    }

    public function decryptGeneral(#[\SensitiveParameter] string $token, string $kid): string
    {
        $document = $this->decodeDocument($token);
        if (!is_string($document['protected'] ?? null) || !is_array($document['recipients'] ?? null)
            || !is_string($document['iv'] ?? null) || !is_string($document['ciphertext'] ?? null)
            || !is_string($document['tag'] ?? null) || count($document['recipients']) > 32) {
            throw new InvalidTokenException('General JWE structure is invalid.');
        }
        $header = $this->decodeProtected($document['protected']);
        $this->validateProtected($header);
        if (!is_array($header['kids'] ?? null) || !in_array($kid, $header['kids'], true)) {
            throw new InvalidTokenException('General JWE protected recipient identifiers are invalid.');
        }
        $recipient = $this->recipient($document['recipients'], $kid);
        $recipientHeader = $recipient['header'];
        unset($recipientHeader['kid']);
        if (array_intersect_key($header, $recipientHeader) !== []) {
            throw new InvalidTokenException('General JWE header parameter names must be disjoint.');
        }
        $cek = new JweKeyManager()->unwrap(
            $this->algorithm,
            $this->key,
            $this->decodeEncryptedKey($recipient['encrypted_key']),
            $header + $recipientHeader,
        );

        return new JweContentCipher()->decrypt(
            $this->decodeSegment($document['ciphertext'], 'ciphertext'),
            $cek,
            $document['protected'],
            $this->decodeSegment($document['iv'], 'iv'),
            $this->decodeSegment($document['tag'], 'tag'),
        );
    }

    public function decryptNested(string $encryptedJwt): string
    {
        $parts = explode('.', $encryptedJwt);
        if (count($parts) !== 5) {
            throw new InvalidTokenException('Nested JWT outer value must be a compact JWE.');
        }
        $header = $this->decodeProtected($parts[0]);
        if (($header['cty'] ?? null) !== 'JWT') {
            throw new InvalidTokenException('Nested JWT outer JWE must protect cty=JWT.');
        }
        $signed = $this->decryptCompact($encryptedJwt);
        if (count(explode('.', $signed)) !== 3) {
            throw new InvalidTokenException('Nested JWT inner value must be a compact JWS.');
        }

        return $signed;
    }

    /** @param array<string, mixed> $protectedHeaders */
    public function encryptCompact(#[\SensitiveParameter] string $plaintext, array $protectedHeaders = []): string
    {
        $header = $this->protectedHeader($protectedHeaders);
        $wrapped = new JweKeyManager()->wrap($this->algorithm, $this->key, $header);
        $encodedHeader = Base64Url::encode(Json::encode($wrapped['header']));
        $encrypted = new JweContentCipher()->encrypt($plaintext, $wrapped['cek'], $encodedHeader);

        return implode('.', [
            $encodedHeader,
            Base64Url::encode($wrapped['encryptedKey']),
            Base64Url::encode($encrypted['iv']),
            Base64Url::encode($encrypted['ciphertext']),
            Base64Url::encode($encrypted['tag']),
        ]);
    }

    /** @param array<string, mixed> $protectedHeaders */
    public function encryptFlattened(#[\SensitiveParameter] string $plaintext, array $protectedHeaders = []): string
    {
        $header = $this->protectedHeader($protectedHeaders);
        $wrapped = new JweKeyManager()->wrap($this->algorithm, $this->key, $header);
        $encodedHeader = Base64Url::encode(Json::encode($wrapped['header']));
        $encrypted = new JweContentCipher()->encrypt($plaintext, $wrapped['cek'], $encodedHeader);

        $document = [
            'protected' => $encodedHeader,
            'iv' => Base64Url::encode($encrypted['iv']),
            'ciphertext' => Base64Url::encode($encrypted['ciphertext']),
            'tag' => Base64Url::encode($encrypted['tag']),
        ];
        if ($wrapped['encryptedKey'] !== '') {
            $document['encrypted_key'] = Base64Url::encode($wrapped['encryptedKey']);
        }

        return Json::encode($document);
    }

    /**
     * @param non-empty-list<array{key: string, kid: string}> $recipients
     * @param array<string, mixed> $protectedHeaders
     */
    public function encryptGeneral(#[\SensitiveParameter] string $plaintext, array $recipients, array $protectedHeaders = []): string
    {
        if (count($recipients) > 32
            || in_array($this->algorithm, [JweKeyManagementAlgorithm::DIRECT, JweKeyManagementAlgorithm::ECDH_ES], true)) {
            throw new InvalidTokenException('General JWE requires 1-32 recipients and a wrapping key-management algorithm.');
        }
        $kids = array_column($recipients, 'kid');
        if (count(array_unique($kids)) !== count($kids)) {
            throw new InvalidTokenException('General JWE recipient kid values must be unique.');
        }
        $header = $this->protectedHeader($protectedHeaders);
        $header['kids'] = $kids;
        $cek = random_bytes(32);
        $encodedRecipients = [];
        foreach ($recipients as $recipient) {
            $wrapped = new JweKeyManager()->wrap($this->algorithm, $recipient['key'], [], $cek);
            $encodedRecipients[] = [
                'header' => ['kid' => $recipient['kid']] + $wrapped['header'],
                'encrypted_key' => Base64Url::encode($wrapped['encryptedKey']),
            ];
        }
        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encrypted = new JweContentCipher()->encrypt($plaintext, $cek, $encodedHeader);

        return $this->encodeDocument([
            'protected' => $encodedHeader,
            'recipients' => $encodedRecipients,
            'iv' => Base64Url::encode($encrypted['iv']),
            'ciphertext' => Base64Url::encode($encrypted['ciphertext']),
            'tag' => Base64Url::encode($encrypted['tag']),
        ]);
    }

    public function encryptNested(string $signedJwt): string
    {
        if (count(explode('.', $signedJwt)) !== 3) {
            throw new InvalidTokenException('Nested JWT input must be a compact JWS.');
        }

        return $this->encryptCompact($signedJwt, ['cty' => 'JWT']);
    }

    /** @return array<string, mixed> */
    private function decodeDocument(string $token): array
    {
        if ($token === '' || strlen($token) > self::MAX_CIPHERTEXT_BYTES) {
            throw new InvalidTokenException('JWE JSON serialization exceeds its size bound.');
        }

        return JwtToken::decodeJsonObject($token, 'JWE JSON serialization');
    }

    private function decodeEncryptedKey(string $encoded): string
    {
        return $encoded === '' ? '' : $this->decodeSegment($encoded, 'encrypted key');
    }

    /** @return array<string, mixed> */
    private function decodeProtected(string $encoded): array
    {
        try {
            return JwtToken::decodeJsonObject(Base64Url::decode($encoded), 'JWE protected header');
        } catch (\Throwable $exception) {
            throw new InvalidTokenException('JWE protected header is invalid.', 0, $exception);
        }
    }

    private function decodeSegment(string $encoded, string $name): string
    {
        try {
            return Base64Url::decode($encoded);
        } catch (\Throwable $exception) {
            throw new InvalidTokenException(sprintf('JWE %s is not valid Base64URL.', $name), 0, $exception);
        }
    }

    /** @param array<mixed, mixed> $document */
    private function encodeDocument(array $document): string
    {
        $normalized = [];
        foreach ($document as $name => $value) {
            if (is_string($name)) {
                $normalized[$name] = $value;
            }
        }

        return Json::encode($normalized);
    }

    /**
     * @param array<string, mixed> $additional
     * @return array<string, mixed>
     */
    private function protectedHeader(array $additional): array
    {
        foreach (['alg', 'enc', 'kid', 'zip', 'iv', 'tag', 'epk', 'kids'] as $reserved) {
            if (array_key_exists($reserved, $additional)) {
                throw new InvalidTokenException(sprintf('JWE protected header %s is managed by the configured capability.', $reserved));
            }
        }

        $header = [
            'alg' => $this->algorithm->value,
            'enc' => $this->contentEncryption->value,
            ...($this->keyId === null ? [] : ['kid' => $this->keyId]),
        ];
        foreach ($additional as $name => $value) {
            $header[$name] = $value;
        }

        return $header;
    }

    /**
     * @param array<mixed> $recipients
     * @return array{header: array<string, mixed>, encrypted_key: string}
     */
    private function recipient(array $recipients, string $kid): array
    {
        $match = null;
        foreach ($recipients as $candidate) {
            if (!is_array($candidate) || !is_array($candidate['header'] ?? null)
                || !is_string($candidate['encrypted_key'] ?? null) || ($candidate['header']['kid'] ?? null) !== $kid) {
                continue;
            }
            if ($match !== null) {
                throw new InvalidTokenException('General JWE contains a duplicate recipient kid.');
            }
            $header = [];
            foreach ($candidate['header'] as $name => $value) {
                if (is_string($name)) {
                    $header[$name] = $value;
                }
            }
            $match = ['header' => $header, 'encrypted_key' => $candidate['encrypted_key']];
        }
        if ($match === null) {
            throw new InvalidTokenException(sprintf('General JWE has no recipient for kid %s.', $kid));
        }

        return $match;
    }

    /** @param array<string, mixed> $header */
    private function validateProtected(array $header): void
    {
        if (($header['alg'] ?? null) !== $this->algorithm->value
            || ($header['enc'] ?? null) !== $this->contentEncryption->value
            || isset($header['zip']) || ($this->keyId !== null && ($header['kid'] ?? null) !== $this->keyId)) {
            throw new InvalidTokenException('JWE protected algorithms, kid, or compression policy is invalid.');
        }
    }
}
