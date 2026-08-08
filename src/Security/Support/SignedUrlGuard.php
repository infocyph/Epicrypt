<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Enum\SignedUrlVersion;
use Infocyph\Epicrypt\Security\SignedUrlOptions;
use Infocyph\Epicrypt\Security\SignedUrlVerificationResult;

/**
 * @phpstan-type QueryScalar bool|float|int|string
 * @phpstan-type QueryArray array<array-key, QueryScalar>
 * @phpstan-type QueryMap array<string, QueryScalar|QueryArray>
 */
final class SignedUrlGuard
{
    /**
     * @param array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed} $parts
     */
    public static function assertUrlPolicy(array $parts, SignedUrlOptions $options, bool $throwOnFailure): bool
    {
        $host = isset($parts['host']) && is_string($parts['host']) ? strtolower(trim($parts['host'])) : '';
        $scheme = isset($parts['scheme']) && is_string($parts['scheme']) ? strtolower(trim($parts['scheme'])) : '';
        $isAbsolute = $host !== '' || $scheme !== '';
        $isRelative = !$isAbsolute;

        if (!self::assertAbsoluteRelativePolicy($isAbsolute, $isRelative, $options, $throwOnFailure)) {
            return false;
        }

        if (!self::assertBindingPolicy($host, $scheme, $isAbsolute, $isRelative, $options, $throwOnFailure)) {
            return false;
        }

        if (!self::assertAllowedHostPolicy($host, $options, $throwOnFailure)) {
            return false;
        }

        return true;
    }

    /**
     * @param QueryMap $query
     */
    public static function expiresAtFromQuery(array $query, string $expiresParam): ?int
    {
        if (!isset($query[$expiresParam])) {
            return null;
        }

        return self::parseTimestamp($query[$expiresParam]);
    }

    /**
     * @param QueryMap $query
     * @return array{signature: string, version: ?int}|null
     */
    public static function extractSignatureData(array $query, string $signatureParam, string $versionParam): ?array
    {
        $signature = $query[$signatureParam] ?? null;
        if (!is_string($signature) || $signature === '') {
            return null;
        }

        $version = null;
        if (isset($query[$versionParam])) {
            $version = self::parseVersion($query[$versionParam]);
            if ($version === null) {
                return null;
            }
        }

        return ['signature' => $signature, 'version' => $version];
    }

    public static function invalidSignatureResult(?int $expiresAt = null, ?int $version = null): SignedUrlVerificationResult
    {
        return new SignedUrlVerificationResult(false, invalidSignature: true, expiresAt: $expiresAt, version: $version);
    }

    /**
     * @param QueryMap $query
     */
    public static function validateExpirationFromQuery(array $query, string $expiresParam, int $now, ?int $version): ?SignedUrlVerificationResult
    {
        if (!isset($query[$expiresParam])) {
            return null;
        }

        $expiresAt = self::parseTimestamp($query[$expiresParam]);
        if ($expiresAt === null) {
            return self::invalidSignatureResult(version: $version);
        }

        if ($now > $expiresAt) {
            return new SignedUrlVerificationResult(false, expired: true, expiresAt: $expiresAt, version: $version);
        }

        return null;
    }

    /**
     * @param QueryMap $query
     */
    public static function validateMethodFromQuery(array $query, string $methodParam, SignedUrlOptions $options, ?int $expiresAt, ?int $version): ?SignedUrlVerificationResult
    {
        $methodValue = $query[$methodParam] ?? null;
        if ($methodValue === null) {
            return $options->method === null ? null : self::invalidSignatureResult($expiresAt, $version);
        }

        if (!is_string($methodValue) || $methodValue === '') {
            return self::invalidSignatureResult($expiresAt, $version);
        }

        if ($options->method !== null && strtoupper($methodValue) !== $options->method) {
            return self::invalidSignatureResult($expiresAt, $version);
        }

        return null;
    }

    private static function assertAbsoluteRelativePolicy(bool $isAbsolute, bool $isRelative, SignedUrlOptions $options, bool $throwOnFailure): bool
    {
        if ($isAbsolute && !$options->allowAbsoluteUrls) {
            return self::policyFailure('Absolute signed URLs are not allowed by policy.', $throwOnFailure);
        }

        if ($isRelative && !$options->allowRelativeUrls) {
            return self::policyFailure('Relative signed URLs are not allowed by policy.', $throwOnFailure);
        }

        return true;
    }

    private static function assertAllowedHostPolicy(string $host, SignedUrlOptions $options, bool $throwOnFailure): bool
    {
        if ($options->allowedHosts !== null && $host !== '' && !in_array($host, $options->allowedHosts, true)) {
            return self::policyFailure('Host is not in the allowed host list for signed URLs.', $throwOnFailure);
        }

        return true;
    }

    private static function assertBindingPolicy(string $host, string $scheme, bool $isAbsolute, bool $isRelative, SignedUrlOptions $options, bool $throwOnFailure): bool
    {
        if ($isRelative && ($options->bindHost || $options->bindScheme)) {
            return self::policyFailure('Relative signed URLs require host and scheme binding to be disabled.', $throwOnFailure);
        }

        if ($options->bindHost && $isAbsolute && $host === '') {
            return self::policyFailure('Host binding requires an absolute URL with a host.', $throwOnFailure);
        }

        if ($options->bindScheme && $isAbsolute && $scheme === '') {
            return self::policyFailure('Scheme binding requires an absolute URL with a scheme.', $throwOnFailure);
        }

        return true;
    }

    private static function parseTimestamp(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        if (!is_string($value) || !preg_match('/^-?[0-9]+$/', $value)) {
            return null;
        }

        return (int) $value;
    }

    private static function parseVersion(mixed $value): ?int
    {
        if (!is_numeric($value)) {
            return null;
        }

        $version = (int) $value;
        if ($version !== SignedUrlVersion::V2->value) {
            return null;
        }

        return $version;
    }

    private static function policyFailure(string $message, bool $throwOnFailure): bool
    {
        if ($throwOnFailure) {
            throw new ConfigurationException($message);
        }

        return false;
    }
}
