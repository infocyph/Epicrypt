<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JosePolicy;
use Infocyph\Epicrypt\Token\Jwt\Support\JwsSignature;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;
use Throwable;

final readonly class Jws
{
    private const string SIGNER = 'signer';

    private const string VERIFIER = 'verifier';

    private JwsSignature $signature;

    private function __construct(
        private string $mode,
        #[\SensitiveParameter]
        string $key,
        private SymmetricJwtAlgorithm|AsymmetricJwtAlgorithm $algorithm,
        private ?string $keyId,
        #[\SensitiveParameter]
        ?string $passphrase,
    ) {
        JosePolicy::assertConfiguredKeyId($this->keyId, 'JWS key id');
        $this->signature = new JwsSignature($key, $this->algorithm, $this->mode === self::SIGNER, $passphrase);
    }

    public static function signer(
        #[\SensitiveParameter]
        string $privateOrSharedKey,
        SymmetricJwtAlgorithm|AsymmetricJwtAlgorithm $algorithm = AsymmetricJwtAlgorithm::ES256,
        ?string $keyId = null,
        #[\SensitiveParameter]
        ?string $passphrase = null,
    ): self {
        return new self(self::SIGNER, $privateOrSharedKey, $algorithm, $keyId, $passphrase);
    }

    /** @param list<self> $signers */
    public static function signGeneral(
        #[\SensitiveParameter]
        string $payload,
        #[\SensitiveParameter]
        array $signers,
        bool $detached = false,
        bool $base64Payload = true,
    ): string {
        JosePolicy::assertParticipantCount(count($signers), 'General JWS');

        $signatures = [];
        $payloadPart = null;
        foreach ($signers as $signer) {
            $signer->requireMode(self::SIGNER);
            [$protected, $candidatePayload, $signature] = $signer->signParts($payload, [], [], $base64Payload);
            $payloadPart ??= $candidatePayload;
            $signatures[] = ['protected' => $protected, 'signature' => $signature];
        }
        $document = ['signatures' => $signatures];
        if (!$detached) {
            $document['payload'] = $payloadPart;
        }
        $encoded = Json::encode($document);
        JosePolicy::assertGeneratedSize($encoded, JosePolicy::MAX_COMPACT_TOKEN_BYTES, 'General JWS serialization');

        return $encoded;
    }

    public static function verifier(
        #[\SensitiveParameter]
        string $publicOrSharedKey,
        SymmetricJwtAlgorithm|AsymmetricJwtAlgorithm $algorithm = AsymmetricJwtAlgorithm::ES256,
        ?string $keyId = null,
    ): self {
        return new self(self::VERIFIER, $publicOrSharedKey, $algorithm, $keyId, null);
    }

    /** @param list<self> $verifiers */
    public static function verifyGeneral(
        #[\SensitiveParameter]
        string $jws,
        #[\SensitiveParameter]
        array $verifiers,
        int $requiredSignatures,
        #[\SensitiveParameter]
        ?string $detachedPayload = null,
    ): bool {
        JosePolicy::assertParticipantCount(count($verifiers), 'General JWS');
        if ($requiredSignatures < 1 || $requiredSignatures > count($verifiers)) {
            throw new ConfigurationException('General JWS signature threshold is invalid.');
        }

        try {
            $document = self::decodeGeneralDocument($jws);
            $signatures = $document['signatures'];
            if ($requiredSignatures > count($signatures)) {
                return false;
            }
            $verified = 0;
            $used = [];
            foreach ($signatures as $entry) {
                foreach ($verifiers as $index => $verifier) {
                    if (isset($used[$index]) || !$verifier->verifyDocumentEntry($document, $entry, $detachedPayload)) {
                        continue;
                    }
                    $used[$index] = true;
                    $verified++;

                    break;
                }
            }

            return $verified >= $requiredSignatures;
        } catch (Throwable) {
            return false;
        }
    }

    /** @param array<string, mixed> $protectedHeaders */
    public function signCompact(
        #[\SensitiveParameter]
        string $payload,
        array $protectedHeaders = [],
        bool $detached = false,
        bool $base64Payload = true,
    ): string {
        $this->requireMode(self::SIGNER);
        [$encodedHeader, $payloadPart, $signature] = $this->signParts($payload, $protectedHeaders, [], $base64Payload);
        if (!$base64Payload && !$detached && str_contains($payload, '.')) {
            throw new ConfigurationException('An embedded unencoded compact JWS payload must not contain a period.');
        }
        $serialized = $encodedHeader . '.' . ($detached ? '' : $payloadPart) . '.' . $signature;
        JosePolicy::assertGeneratedSize($serialized, JosePolicy::MAX_COMPACT_TOKEN_BYTES, 'Compact JWS');

        return $serialized;
    }

    /**
     * @param array<string, mixed> $protectedHeaders
     * @param array<string, mixed> $unprotectedHeaders
     */
    public function signFlattened(
        #[\SensitiveParameter]
        string $payload,
        array $protectedHeaders = [],
        array $unprotectedHeaders = [],
        bool $detached = false,
        bool $base64Payload = true,
    ): string {
        $this->requireMode(self::SIGNER);
        [$encodedHeader, $payloadPart, $signature] = $this->signParts(
            $payload,
            $protectedHeaders,
            $unprotectedHeaders,
            $base64Payload,
        );
        $document = ['protected' => $encodedHeader, 'signature' => $signature];
        if ($unprotectedHeaders !== []) {
            $document['header'] = $unprotectedHeaders;
        }
        if (!$detached) {
            $document['payload'] = $payloadPart;
        }
        $encoded = Json::encode($document);
        JosePolicy::assertGeneratedSize($encoded, JosePolicy::MAX_COMPACT_TOKEN_BYTES, 'Flattened JWS serialization');

        return $encoded;
    }

    public function verifyCompact(
        #[\SensitiveParameter]
        string $jws,
        #[\SensitiveParameter]
        ?string $detachedPayload = null,
    ): bool {
        $this->requireMode(self::VERIFIER);
        if ($jws === '' || strlen($jws) > JosePolicy::MAX_COMPACT_TOKEN_BYTES) {
            return false;
        }
        $parts = explode('.', $jws);
        if (count($parts) !== 3 || $parts[0] === '' || $parts[2] === '') {
            return false;
        }

        return $this->verifyParts($parts[0], $parts[1], $parts[2], [], $detachedPayload);
    }

    public function verifyFlattened(
        #[\SensitiveParameter]
        string $jws,
        #[\SensitiveParameter]
        ?string $detachedPayload = null,
    ): bool {
        $this->requireMode(self::VERIFIER);

        try {
            $document = $this->decodeDocument($jws);

            return $this->verifyDocumentEntry($document, $document, $detachedPayload);
        } catch (Throwable) {
            return false;
        }
    }

    /** @return array{signatures: non-empty-list<array<string, mixed>>, payload?: mixed} */
    private static function decodeGeneralDocument(#[\SensitiveParameter] string $jws): array
    {
        $document = JwtToken::decodeJsonObject(
            $jws,
            'general JWS JSON serialization',
            JosePolicy::MAX_COMPACT_TOKEN_BYTES,
            JosePolicy::MAX_DOCUMENT_MEMBERS,
        );
        $signatures = $document['signatures'] ?? null;
        if (!is_array($signatures) || $signatures === [] || !array_is_list($signatures)) {
            throw new ConfigurationException('General JWS must contain a non-empty signatures list.');
        }
        if (count($signatures) > JosePolicy::MAX_PARTICIPANTS) {
            throw new ConfigurationException('General JWS contains too many signatures.');
        }
        $normalized = [];
        foreach ($signatures as $signature) {
            if (!is_array($signature)) {
                throw new ConfigurationException('General JWS signatures must be objects.');
            }
            $normalized[] = self::stringKeyArray($signature);
        }
        if (array_key_exists('payload', $document)) {
            return ['signatures' => $normalized, 'payload' => $document['payload']];
        }

        return ['signatures' => $normalized];
    }

    /**
     * @param array<mixed, mixed> $input
     * @return array<string, mixed>
     */
    private static function stringKeyArray(array $input): array
    {
        $normalized = [];
        foreach ($input as $key => $value) {
            if (is_string($key)) {
                $normalized[$key] = $value;
            }
        }

        return $normalized;
    }

    /**
     * @param array<string, mixed> $protectedHeaders
     * @return array<string, mixed>
     */
    private function applyPayloadEncodingHeaders(array $protectedHeaders, bool $base64Payload): array
    {
        if (!$base64Payload) {
            $protectedHeaders['b64'] = false;
            $critical = $protectedHeaders['crit'] ?? [];
            if (!is_array($critical) || !array_is_list($critical) || ($critical !== [] && $critical !== ['b64'])) {
                throw new ConfigurationException('JWS only supports b64 as a critical extension.');
            }
            $protectedHeaders['crit'] = ['b64'];
        } elseif (isset($protectedHeaders['b64']) || isset($protectedHeaders['crit'])) {
            throw new ConfigurationException('JWS b64 and crit are only valid for an unencoded payload.');
        }

        return $protectedHeaders;
    }

    /** @return array<string, mixed> */
    private function decodeDocument(#[\SensitiveParameter] string $jws): array
    {
        return JwtToken::decodeJsonObject(
            $jws,
            'JWS JSON serialization',
            JosePolicy::MAX_COMPACT_TOKEN_BYTES,
            JosePolicy::MAX_DOCUMENT_MEMBERS,
        );
    }

    /**
     * @param array<string, mixed> $protectedHeaders
     * @param array<string, mixed> $unprotectedHeaders
     * @return array<string, mixed>
     */
    private function normalizedProtectedHeaders(
        array $protectedHeaders,
        array $unprotectedHeaders,
        bool $base64Payload,
    ): array {
        $this->validateSigningHeaders($protectedHeaders, $unprotectedHeaders);
        $protectedHeaders['alg'] = $this->algorithm->value;
        if ($this->keyId !== null) {
            $protectedHeaders['kid'] = $this->keyId;
        }
        $protectedHeaders = $this->applyPayloadEncodingHeaders($protectedHeaders, $base64Payload);
        JosePolicy::assertConfiguredMemberCount($protectedHeaders, JosePolicy::MAX_HEADER_MEMBERS, 'JWS protected header');

        return $protectedHeaders;
    }

    private function requireMode(string $mode): void
    {
        if ($this->mode !== $mode) {
            throw new ConfigurationException(sprintf('This JWS instance is not configured as a %s.', $mode));
        }
    }

    /**
     * @param array<string, mixed> $protectedHeaders
     * @param array<string, mixed> $unprotectedHeaders
     * @return array{string, string, string}
     */
    private function signParts(
        #[\SensitiveParameter]
        string $payload,
        array $protectedHeaders,
        array $unprotectedHeaders,
        bool $base64Payload,
    ): array {
        JosePolicy::assertConfiguredMemberCount($unprotectedHeaders, JosePolicy::MAX_HEADER_MEMBERS, 'JWS unprotected header');
        $protected = $this->normalizedProtectedHeaders($protectedHeaders, $unprotectedHeaders, $base64Payload);
        $headerJson = Json::encode($protected);
        JosePolicy::assertGeneratedSize($headerJson, JosePolicy::MAX_HEADER_BYTES, 'JWS protected header');
        $encodedHeader = Base64Url::encode($headerJson);
        $payloadPart = $base64Payload ? Base64Url::encode($payload) : $payload;
        $signature = $this->signature->sign($encodedHeader . '.' . $payloadPart);

        return [$encodedHeader, $payloadPart, Base64Url::encode($signature)];
    }

    /**
     * @param array<string, mixed> $protected
     * @param array<string, mixed> $unprotected
     */
    private function validateProtectedHeaders(array $protected, array $unprotected): bool
    {
        if (array_intersect_key($protected, $unprotected) !== [] || ($protected['alg'] ?? null) !== $this->algorithm->value) {
            throw new ConfigurationException('JWS protected headers are invalid.');
        }
        foreach (['alg', 'b64', 'crit', 'kid'] as $header) {
            if (array_key_exists($header, $unprotected)) {
                throw new ConfigurationException(sprintf('JWS %s must be integrity protected.', $header));
            }
        }
        if ($this->keyId !== null && ($protected['kid'] ?? null) !== $this->keyId) {
            throw new ConfigurationException('JWS kid does not match the configured verifier.');
        }
        if (isset($protected['kid']) && (!is_string($protected['kid']) || !JosePolicy::isKeyId($protected['kid']))) {
            throw new ConfigurationException('JWS kid is invalid.');
        }
        $base64Payload = $protected['b64'] ?? true;
        if (!is_bool($base64Payload)) {
            throw new ConfigurationException('JWS b64 must be boolean.');
        }
        if (!$base64Payload && ($protected['crit'] ?? null) !== ['b64']) {
            throw new ConfigurationException('Unencoded JWS payload requires crit=["b64"].');
        }
        if ($base64Payload && isset($protected['crit'])) {
            throw new ConfigurationException('Unknown or unnecessary JWS critical headers are not supported.');
        }

        return $base64Payload;
    }

    /**
     * @param array<string, mixed> $protectedHeaders
     * @param array<string, mixed> $unprotectedHeaders
     */
    private function validateSigningHeaders(array $protectedHeaders, array $unprotectedHeaders): void
    {
        if (array_intersect_key($protectedHeaders, $unprotectedHeaders) !== []) {
            throw new ConfigurationException('JWS protected and unprotected header names must be disjoint.');
        }
        foreach (['alg', 'b64', 'crit', 'kid'] as $securityHeader) {
            if (array_key_exists($securityHeader, $unprotectedHeaders)) {
                throw new ConfigurationException(sprintf('JWS %s must be integrity protected.', $securityHeader));
            }
        }
        if (isset($protectedHeaders['alg']) && $protectedHeaders['alg'] !== $this->algorithm->value) {
            throw new ConfigurationException('JWS alg does not match the configured signer.');
        }
        if (isset($protectedHeaders['kid'])
            && (!is_string($protectedHeaders['kid']) || !JosePolicy::isKeyId($protectedHeaders['kid']))) {
            throw new ConfigurationException('JWS kid is invalid.');
        }
        if ($this->keyId !== null && isset($protectedHeaders['kid']) && $protectedHeaders['kid'] !== $this->keyId) {
            throw new ConfigurationException('JWS kid does not match the configured signer.');
        }
    }

    /**
     * @param array<string, mixed> $document
     * @param array<string, mixed> $entry
     */
    private function verifyDocumentEntry(
        #[\SensitiveParameter]
        array $document,
        array $entry,
        #[\SensitiveParameter]
        ?string $detachedPayload,
    ): bool {
        $protected = $entry['protected'] ?? null;
        $signature = $entry['signature'] ?? null;
        $unprotected = $entry['header'] ?? [];
        if (!is_string($protected) || $protected === '' || !is_string($signature) || $signature === '' || !is_array($unprotected)) {
            return false;
        }
        $hasEmbeddedPayload = array_key_exists('payload', $document);
        $payload = $hasEmbeddedPayload ? $document['payload'] : null;
        if ($hasEmbeddedPayload && !is_string($payload)) {
            return false;
        }
        if (!$hasEmbeddedPayload && $detachedPayload === null) {
            return false;
        }

        return $this->verifyParts(
            $protected,
            is_string($payload) ? $payload : '',
            $signature,
            self::stringKeyArray($unprotected),
            $hasEmbeddedPayload ? null : $detachedPayload,
        );
    }

    /** @param array<string, mixed> $unprotectedHeaders */
    private function verifyParts(
        string $encodedHeader,
        #[\SensitiveParameter]
        string $payloadPart,
        string $encodedSignature,
        array $unprotectedHeaders,
        #[\SensitiveParameter]
        ?string $detachedPayload,
    ): bool {
        try {
            $protected = JwtToken::decodeJsonObject(
                Base64Url::decode($encodedHeader),
                'JWS protected header',
                JosePolicy::MAX_HEADER_BYTES,
                JosePolicy::MAX_HEADER_MEMBERS,
            );
            JosePolicy::assertMemberCount($unprotectedHeaders, JosePolicy::MAX_HEADER_MEMBERS, 'JWS unprotected header');
            $base64Payload = $this->validateProtectedHeaders($protected, $unprotectedHeaders);
            if ($detachedPayload !== null) {
                if ($payloadPart !== '') {
                    return false;
                }
                $payloadPart = $base64Payload ? Base64Url::encode($detachedPayload) : $detachedPayload;
            }

            return $this->signature->verify($encodedHeader . '.' . $payloadPart, Base64Url::decode($encodedSignature));
        } catch (Throwable) {
            return false;
        }
    }
}
