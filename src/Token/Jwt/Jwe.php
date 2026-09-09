<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweContentEncryptionAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JosePolicy;
use Infocyph\Epicrypt\Token\Jwt\Support\JweContentCipher;
use Infocyph\Epicrypt\Token\Jwt\Support\JweKeyManager;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;

final readonly class Jwe
{
    public function __construct(
        #[\SensitiveParameter]
        private string $key,
        private JweKeyManagementAlgorithm $algorithm = JweKeyManagementAlgorithm::DIRECT,
        private JweContentEncryptionAlgorithm $contentEncryption = JweContentEncryptionAlgorithm::A256GCM,
        private ?string $keyId = null,
    ) {
        JosePolicy::assertConfiguredKeyId($this->keyId, 'JWE key id');
        if ($key === '') {
            throw new ConfigurationException('JWE key must not be empty.');
        }
        if ((in_array($this->algorithm, [JweKeyManagementAlgorithm::DIRECT, JweKeyManagementAlgorithm::A256KW, JweKeyManagementAlgorithm::A256GCMKW], true)
                || in_array($this->algorithm, [JweKeyManagementAlgorithm::ECDH_ES, JweKeyManagementAlgorithm::ECDH_ES_A256KW], true))
            && strlen($key) !== 32) {
            throw new ConfigurationException('The selected JWE key-management algorithm requires a 32-byte key.');
        }
    }

    public function decryptCompact(#[\SensitiveParameter] string $token): string
    {
        JosePolicy::assertInputSize($token, JosePolicy::MAX_JWE_SERIALIZED_BYTES, 'JWE compact serialization');
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
        if (!JosePolicy::isKeyId($kid)) {
            throw new InvalidTokenException('General JWE recipient kid is invalid.');
        }
        $document = $this->decodeDocument($token);
        if (!is_string($document['protected'] ?? null) || !is_array($document['recipients'] ?? null)
            || !is_string($document['iv'] ?? null) || !is_string($document['ciphertext'] ?? null)
            || !is_string($document['tag'] ?? null)
            || count($document['recipients']) < 1
            || count($document['recipients']) > JosePolicy::MAX_PARTICIPANTS) {
            throw new InvalidTokenException('General JWE structure is invalid.');
        }
        $header = $this->decodeProtected($document['protected']);
        $this->validateProtected($header, recipientKeyId: true);
        $sharedHeader = $document['unprotected'] ?? [];
        if (!is_array($sharedHeader)) {
            throw new InvalidTokenException('General JWE shared unprotected header must be an object.');
        }
        $sharedHeader = $this->stringKeyArray($sharedHeader);
        JosePolicy::assertMemberCount($sharedHeader, JosePolicy::MAX_HEADER_MEMBERS, 'General JWE shared header');
        if (array_intersect_key($header, $sharedHeader) !== []) {
            throw new InvalidTokenException('General JWE protected and shared header names must be disjoint.');
        }
        $this->validateRecipientSet($document['recipients'], $header, $sharedHeader);
        $recipient = $this->recipient($document['recipients'], $kid);
        $recipientHeader = $recipient['header'];
        if (array_intersect_key($header + $sharedHeader, $recipientHeader) !== []) {
            throw new InvalidTokenException('General JWE header parameter names must be disjoint.');
        }
        $cek = new JweKeyManager()->unwrap(
            $this->algorithm,
            $this->key,
            $this->decodeEncryptedKey($recipient['encrypted_key']),
            $header + $sharedHeader + $recipientHeader,
        );

        return new JweContentCipher()->decrypt(
            $this->decodeSegment($document['ciphertext'], 'ciphertext'),
            $cek,
            $document['protected'],
            $this->decodeSegment($document['iv'], 'iv'),
            $this->decodeSegment($document['tag'], 'tag'),
        );
    }

    public function decryptNested(#[\SensitiveParameter] string $encryptedJwt): string
    {
        JosePolicy::assertInputSize($encryptedJwt, JosePolicy::MAX_JWE_SERIALIZED_BYTES, 'Nested JWT outer JWE');
        $parts = explode('.', $encryptedJwt);
        if (count($parts) !== 5) {
            throw new InvalidTokenException('Nested JWT outer value must be a compact JWE.');
        }
        $header = $this->decodeProtected($parts[0]);
        if (($header['cty'] ?? null) !== 'JWT') {
            throw new InvalidTokenException('Nested JWT outer JWE must protect cty=JWT.');
        }
        $signed = $this->decryptCompact($encryptedJwt);
        JosePolicy::assertInputSize($signed, JosePolicy::MAX_COMPACT_TOKEN_BYTES, 'Nested JWT inner JWS');
        if (count(explode('.', $signed)) !== 3) {
            throw new InvalidTokenException('Nested JWT inner value must be a compact JWS.');
        }

        return $signed;
    }

    /** @param array<string, mixed> $protectedHeaders */
    public function encryptCompact(#[\SensitiveParameter] string $plaintext, array $protectedHeaders = []): string
    {
        $this->assertPlaintextSize($plaintext);
        $header = $this->protectedHeader($protectedHeaders);
        $wrapped = new JweKeyManager()->wrap($this->algorithm, $this->key, $header);
        $encodedHeader = $this->encodeProtectedHeader($wrapped['header']);
        $encrypted = new JweContentCipher()->encrypt($plaintext, $wrapped['cek'], $encodedHeader);
        $serialized = implode('.', [
            $encodedHeader,
            Base64Url::encode($wrapped['encryptedKey']),
            Base64Url::encode($encrypted['iv']),
            Base64Url::encode($encrypted['ciphertext']),
            Base64Url::encode($encrypted['tag']),
        ]);
        JosePolicy::assertGeneratedSize($serialized, JosePolicy::MAX_JWE_SERIALIZED_BYTES, 'JWE compact serialization');

        return $serialized;
    }

    /** @param array<string, mixed> $protectedHeaders */
    public function encryptFlattened(#[\SensitiveParameter] string $plaintext, array $protectedHeaders = []): string
    {
        $this->assertPlaintextSize($plaintext);
        $header = $this->protectedHeader($protectedHeaders);
        $wrapped = new JweKeyManager()->wrap($this->algorithm, $this->key, $header);
        $encodedHeader = $this->encodeProtectedHeader($wrapped['header']);
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

        return $this->encodeDocument($document);
    }

    /**
     * @param list<mixed> $recipients
     * @param array<string, mixed> $protectedHeaders
     */
    public function encryptGeneral(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        array $recipients,
        array $protectedHeaders = [],
    ): string {
        $this->assertPlaintextSize($plaintext);
        JosePolicy::assertParticipantCount(count($recipients), 'General JWE');
        if (in_array($this->algorithm, [JweKeyManagementAlgorithm::DIRECT, JweKeyManagementAlgorithm::ECDH_ES], true)) {
            throw new ConfigurationException('General JWE requires a wrapping key-management algorithm.');
        }
        $validatedRecipients = [];
        foreach ($recipients as $recipient) {
            if (!is_array($recipient)
                || !is_string($recipient['key'] ?? null) || $recipient['key'] === ''
                || !is_string($recipient['kid'] ?? null)
                || !JosePolicy::isKeyId($recipient['kid'])) {
                throw new ConfigurationException('General JWE recipients require valid keys and key identifiers.');
            }
            $validatedRecipients[] = ['key' => $recipient['key'], 'kid' => $recipient['kid']];
        }
        $kids = array_column($validatedRecipients, 'kid');
        if (count(array_unique($kids)) !== count($kids)) {
            throw new ConfigurationException('General JWE recipient kid values must be unique.');
        }
        $header = $this->protectedHeader($protectedHeaders);
        unset($header['kid']);
        $cek = random_bytes(32);

        try {
            $encodedRecipients = [];
            foreach ($validatedRecipients as $recipient) {
                $wrapped = new JweKeyManager()->wrap($this->algorithm, $recipient['key'], [], $cek);
                $recipientHeader = ['kid' => $recipient['kid']] + $wrapped['header'];
                JosePolicy::assertConfiguredMemberCount($recipientHeader, JosePolicy::MAX_HEADER_MEMBERS, 'General JWE recipient header');
                $encodedRecipients[] = [
                    'header' => $recipientHeader,
                    'encrypted_key' => Base64Url::encode($wrapped['encryptedKey']),
                ];
            }
            $encodedHeader = $this->encodeProtectedHeader($header);
            $encrypted = new JweContentCipher()->encrypt($plaintext, $cek, $encodedHeader);

            return $this->encodeDocument([
                'protected' => $encodedHeader,
                'recipients' => $encodedRecipients,
                'iv' => Base64Url::encode($encrypted['iv']),
                'ciphertext' => Base64Url::encode($encrypted['ciphertext']),
                'tag' => Base64Url::encode($encrypted['tag']),
            ]);
        } finally {
            sodium_memzero($cek);
        }
    }

    public function encryptNested(#[\SensitiveParameter] string $signedJwt): string
    {
        JosePolicy::assertInputSize($signedJwt, JosePolicy::MAX_COMPACT_TOKEN_BYTES, 'Nested JWT input JWS');
        if (count(explode('.', $signedJwt)) !== 3) {
            throw new InvalidTokenException('Nested JWT input must be a compact JWS.');
        }

        return $this->encryptCompact($signedJwt, ['cty' => 'JWT']);
    }

    private function assertPlaintextSize(#[\SensitiveParameter] string $plaintext): void
    {
        JosePolicy::assertMaximumConfiguredSize($plaintext, JosePolicy::MAX_JWE_PLAINTEXT_BYTES, 'JWE plaintext');
    }

    /** @return array<string, mixed> */
    private function decodeDocument(#[\SensitiveParameter] string $token): array
    {
        return JwtToken::decodeJsonObject(
            $token,
            'JWE JSON serialization',
            JosePolicy::MAX_JWE_SERIALIZED_BYTES,
            JosePolicy::MAX_DOCUMENT_MEMBERS,
        );
    }

    private function decodeEncryptedKey(string $encoded): string
    {
        return $encoded === '' ? '' : $this->decodeSegment($encoded, 'encrypted key');
    }

    /** @return array<string, mixed> */
    private function decodeProtected(string $encoded): array
    {
        try {
            return JwtToken::decodeJsonObject(
                Base64Url::decode($encoded),
                'JWE protected header',
                JosePolicy::MAX_HEADER_BYTES,
                JosePolicy::MAX_HEADER_MEMBERS,
            );
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
        JosePolicy::assertConfiguredMemberCount($normalized, JosePolicy::MAX_DOCUMENT_MEMBERS, 'JWE JSON serialization');
        $encoded = Json::encode($normalized);
        JosePolicy::assertGeneratedSize($encoded, JosePolicy::MAX_JWE_SERIALIZED_BYTES, 'JWE JSON serialization');

        return $encoded;
    }

    /** @param array<string, mixed> $header */
    private function encodeProtectedHeader(array $header): string
    {
        JosePolicy::assertConfiguredMemberCount($header, JosePolicy::MAX_HEADER_MEMBERS, 'JWE protected header');
        $json = Json::encode($header);
        JosePolicy::assertGeneratedSize($json, JosePolicy::MAX_HEADER_BYTES, 'JWE protected header');

        return Base64Url::encode($json);
    }

    /**
     * @param array<string, mixed> $additional
     * @return array<string, mixed>
     */
    private function protectedHeader(array $additional): array
    {
        JosePolicy::assertConfiguredMemberCount($additional, JosePolicy::MAX_HEADER_MEMBERS, 'JWE protected header');
        foreach (['alg', 'enc', 'kid', 'zip', 'iv', 'tag', 'epk', 'crit'] as $reserved) {
            if (array_key_exists($reserved, $additional)) {
                throw new ConfigurationException(sprintf('JWE protected header %s is managed by the configured capability.', $reserved));
            }
        }

        return [
            'alg' => $this->algorithm->value,
            'enc' => $this->contentEncryption->value,
            ...($this->keyId === null ? [] : ['kid' => $this->keyId]),
            ...$additional,
        ];
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
            $header = $this->stringKeyArray($candidate['header']);
            JosePolicy::assertMemberCount($header, JosePolicy::MAX_HEADER_MEMBERS, 'General JWE recipient header');
            $match = ['header' => $header, 'encrypted_key' => $candidate['encrypted_key']];
        }
        if ($match === null) {
            throw new InvalidTokenException('General JWE has no recipient for the requested kid.');
        }

        return $match;
    }

    /**
     * @param array<mixed, mixed> $input
     * @return array<string, mixed>
     */
    private function stringKeyArray(array $input): array
    {
        $normalized = [];
        foreach ($input as $name => $value) {
            if (is_string($name)) {
                $normalized[$name] = $value;
            }
        }

        return $normalized;
    }

    /** @param array<string, mixed> $header */
    private function validateProtected(array $header, bool $recipientKeyId = false): void
    {
        if (($header['alg'] ?? null) !== $this->algorithm->value
            || ($header['enc'] ?? null) !== $this->contentEncryption->value
            || isset($header['zip'])
            || array_key_exists('crit', $header)
            || (!$recipientKeyId && $this->keyId !== null && ($header['kid'] ?? null) !== $this->keyId)
            || (isset($header['kid']) && (!is_string($header['kid']) || !JosePolicy::isKeyId($header['kid'])))) {
            throw new InvalidTokenException('JWE protected algorithms, kid, or compression policy is invalid.');
        }
    }

    /**
     * @param array<mixed> $recipients
     * @param array<string, mixed> $protected
     * @param array<string, mixed> $shared
     */
    private function validateRecipientSet(array $recipients, array $protected, array $shared): void
    {
        if (count($recipients) < 1 || count($recipients) > JosePolicy::MAX_PARTICIPANTS) {
            throw new InvalidTokenException('General JWE recipient count is invalid.');
        }
        $seen = [];
        foreach ($recipients as $candidate) {
            if (!is_array($candidate) || !is_array($candidate['header'] ?? null) || !is_string($candidate['encrypted_key'] ?? null)) {
                throw new InvalidTokenException('General JWE recipient structure is invalid.');
            }
            $header = $this->stringKeyArray($candidate['header']);
            JosePolicy::assertMemberCount($header, JosePolicy::MAX_HEADER_MEMBERS, 'General JWE recipient header');
            $kid = $header['kid'] ?? null;
            if (!is_string($kid) || !JosePolicy::isKeyId($kid) || isset($seen[$kid])) {
                throw new InvalidTokenException('General JWE recipient kid values must be valid and unique.');
            }
            if (array_intersect_key($protected + $shared, $header) !== []) {
                throw new InvalidTokenException('General JWE header parameter names must be disjoint.');
            }
            $seen[$kid] = true;
        }
    }
}
