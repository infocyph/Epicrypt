from pathlib import Path


def replace(path: str, old: str, new: str, count: int = -1) -> None:
    file = Path(path)
    text = file.read_text()
    occurrences = text.count(old)
    if occurrences == 0:
        raise SystemExit(f"missing replacement anchor in {path}: {old[:80]!r}")
    if count >= 0 and occurrences != count:
        raise SystemExit(f"unexpected replacement count in {path}: expected {count}, got {occurrences}")
    file.write_text(text.replace(old, new))


# Secret-bearing identifiers stay redacted rather than weakening the redaction guard.
replace(
    "src/Auth/Personal/PersonalAccessTokenManager.php",
    "public function revoke(string $tokenId, string $subject): ?PersonalAccessTokenRecord",
    "public function revoke(#[\\SensitiveParameter] string $tokenId, string $subject): ?PersonalAccessTokenRecord",
    1,
)
replace(
    "src/Auth/Personal/PersonalAccessTokenUsageStoreInterface.php",
    "        string $tokenId,\n        string $subject,\n        int $usedAt,",
    "        #[\\SensitiveParameter]\n        string $tokenId,\n        string $subject,\n        int $usedAt,",
    1,
)
replace(
    "src/Auth/Personal/PersonalAccessTokenUsageStoreInterface.php",
    "public function lastUsedAt(string $tokenId, string $subject): ?int;",
    "public function lastUsedAt(#[\\SensitiveParameter] string $tokenId, string $subject): ?int;",
    1,
)
replace(
    "src/Token/Jwt/JwtPolicy.php",
    "        ?AuthTokenClass $tokenClass,\n    ): void {",
    "        #[\\SensitiveParameter]\n        ?AuthTokenClass $tokenClass,\n    ): void {",
    4,
)
replace(
    "src/Token/Jwt/JwtPolicy.php",
    "private static function validateUnclassifiedProfile(?AuthTokenClass $tokenClass): void",
    "private static function validateUnclassifiedProfile(#[\\SensitiveParameter] ?AuthTokenClass $tokenClass): void",
    1,
)

# PHPStan iterable contracts.
replace(
    "src/Auth/OAuth/OAuthAuthorizationInteraction.php",
    "    private function __construct(\n",
    "    /** @param array<array-key, mixed> $authenticationMethods */\n    private function __construct(\n",
    1,
)
replace(
    "src/Auth/Oidc/OpenIdAuthorizationRequest.php",
    "    /** @param array<array-key, mixed> $prompts @return list<OpenIdPrompt> */",
    "    /**\n     * @param array<array-key, mixed> $prompts\n     * @return list<OpenIdPrompt>\n     */",
    1,
)
replace(
    "src/Auth/Oidc/OpenIdAuthorizationRequest.php",
    "    /** @param array<array-key, mixed> $acrValues @return list<string> */",
    "    /**\n     * @param array<array-key, mixed> $acrValues\n     * @return list<string>\n     */",
    1,
)
replace(
    "src/Auth/Oidc/OpenIdAuthorizationRequestValidator.php",
    "    /** @return list<OpenIdPrompt> */\n    private function prompts(string|array|null $value): array",
    "    /**\n     * @param null|string|list<string> $value\n     * @return list<OpenIdPrompt>\n     */\n    private function prompts(string|array|null $value): array",
    1,
)
replace(
    "src/Auth/Oidc/OpenIdAuthorizationRequestValidator.php",
    "    private function maximumAuthenticationAge(string|array|null $value): ?int",
    "    /** @param null|string|list<string> $value */\n    private function maximumAuthenticationAge(string|array|null $value): ?int",
    1,
)
replace(
    "src/Auth/Oidc/OpenIdAuthorizationRequestValidator.php",
    "    /** @return list<string> */\n    private function acrValues(string|array|null $value): array",
    "    /**\n     * @param null|string|list<string> $value\n     * @return list<string>\n     */\n    private function acrValues(string|array|null $value): array",
    1,
)
replace(
    "src/Auth/Oidc/OpenIdProviderMetadata.php",
    "    /** @param array<array-key, mixed> $claims @return list<string> */",
    "    /**\n     * @param array<array-key, mixed> $claims\n     * @return list<string>\n     */",
    1,
)

# PHPStan knows policy is present when KeyRing resolution is reached.
replace(
    "src/Token/Jwt/AsymmetricJwt.php",
    "$this->policy?->keyPurpose ?? KeyPurpose::JWT_SIGNING",
    "$this->policy->keyPurpose",
    1,
)
replace(
    "src/Token/Jwt/SymmetricJwt.php",
    "$this->policy?->keyPurpose ?? KeyPurpose::JWT_SIGNING",
    "$this->policy->keyPurpose",
    1,
)

# Keep interface-required parameters visibly consumed for PHPCS.
replace(
    "tests/Support/InMemoryJwtReplayStore.php",
    "    public function isRevoked(string $namespace, string $tokenId, int $expiresAt): bool\n    {\n        return isset(",
    "    public function isRevoked(string $namespace, string $tokenId, int $expiresAt): bool\n    {\n        unset($expiresAt);\n\n        return isset(",
    1,
)
replace(
    "src/Auth/Oidc/OpenIdTokenResponseExtension.php",
    "    ): array {\n        if (!in_array(",
    "    ): array {\n        unset($authorizationCode);\n\n        if (!in_array(",
    1,
)
replace(
    "src/Auth/OAuth/OAuthSingleAudienceResolver.php",
    "    {\n        return count($client->audiences)",
    "    {\n        unset($scopes);\n\n        return count($client->audiences)",
    1,
)
replace(
    "tests/Auth/OAuth/OAuthAuthorizationSecurityTest.php",
    "        {\n            throw new RuntimeException('adapter failure');",
    "        {\n            unset($client, $scopes);\n\n            throw new RuntimeException('adapter failure');",
    1,
)
replace(
    "tests/Auth/OAuth/OAuthAuthorizationRequestValidatorTest.php",
    "        {\n            return ['billing-api'];",
    "        {\n            unset($client, $scopes);\n\n            return ['billing-api'];",
    1,
)
replace(
    "tests/Auth/OAuth/OAuthAuthorizationRequestValidatorTest.php",
    "        {\n            return ['attacker-api'];",
    "        {\n            unset($client, $scopes);\n\n            return ['attacker-api'];",
    1,
)
replace(
    "tests/Auth/Oidc/OpenIdProviderTest.php",
    "        {\n            return in_array('profile', $scopes, true)",
    "        {\n            unset($principalId, $clientId);\n\n            return in_array('profile', $scopes, true)",
    1,
)
replace(
    "tests/Auth/Oidc/OpenIdProviderTest.php",
    "        {\n            return ['sub' => 'override'];",
    "        {\n            unset($principalId, $clientId, $scopes);\n\n            return ['sub' => 'override'];",
    1,
)

# OAuth access-token issue complexity: isolate authorization and claim construction.
access_path = Path("src/Auth/OAuth/OAuthAccessTokenService.php")
access = access_path.read_text()
old = """        $now = $this->clock->now()->getTimestamp();
        $ttl = $this->lifetimeSeconds;
        if ($authorizationId !== null) {
            $authorization = $this->authorizations->find($authorizationId);
            if (!$authorization instanceof OAuthAuthorizationRecord
                || !$authorization->isActive($now)
                || !$this->authorizationAllows($authorization, $subject, $clientId, $audiences, $scopes)) {
                throw new ConfigurationException('OAuth authorization is not active for the requested access token.');
            }
            $ttl = min($ttl, $authorization->expiresAt - $now);
            if ($ttl < 1) {
                throw new ConfigurationException('OAuth authorization expires before an access token can be issued.');
            }
        }

        $custom = ['client_id' => $clientId];
        if ($scopes !== []) {
            $custom['scope'] = $scopes;
        }
        if ($authorizationId !== null) {
            $custom['authorization_id'] = $authorizationId;
        }
        if ($dpopKeyThumbprint !== null) {
            $custom['cnf'] = ['jkt' => $dpopKeyThumbprint];
        }
"""
new = """        $now = $this->clock->now()->getTimestamp();
        $ttl = $this->authorizedTtl($authorizationId, $subject, $clientId, $audiences, $scopes, $now);
        $custom = self::customClaims($clientId, $scopes, $authorizationId, $dpopKeyThumbprint);
"""
if old not in access:
    raise SystemExit("OAuthAccessTokenService issue anchor missing")
access = access.replace(old, new, 1)
anchor = """    /** @param list<string> $audiences @param list<string> $scopes */
    private function authorizationAllows(
"""
helpers = """    /**
     * @param list<string> $audiences
     * @param list<string> $scopes
     */
    private function authorizedTtl(
        ?string $authorizationId,
        string $subject,
        string $clientId,
        array $audiences,
        array $scopes,
        int $now,
    ): int {
        if ($authorizationId === null) {
            return $this->lifetimeSeconds;
        }

        $authorization = $this->authorizations->find($authorizationId);
        if (!$authorization instanceof OAuthAuthorizationRecord
            || !$authorization->isActive($now)
            || !$this->authorizationAllows($authorization, $subject, $clientId, $audiences, $scopes)) {
            throw new ConfigurationException('OAuth authorization is not active for the requested access token.');
        }

        $ttl = min($this->lifetimeSeconds, $authorization->expiresAt - $now);
        if ($ttl < 1) {
            throw new ConfigurationException('OAuth authorization expires before an access token can be issued.');
        }

        return $ttl;
    }

    /**
     * @param list<string> $scopes
     * @return array<string, mixed>
     */
    private static function customClaims(
        string $clientId,
        array $scopes,
        ?string $authorizationId,
        ?string $dpopKeyThumbprint,
    ): array {
        $custom = ['client_id' => $clientId];
        if ($scopes !== []) {
            $custom['scope'] = $scopes;
        }
        if ($authorizationId !== null) {
            $custom['authorization_id'] = $authorizationId;
        }
        if ($dpopKeyThumbprint !== null) {
            $custom['cnf'] = ['jkt' => $dpopKeyThumbprint];
        }

        return $custom;
    }

    /**
     * @param list<string> $audiences
     * @param list<string> $scopes
     */
    private function authorizationAllows(
"""
if anchor not in access:
    raise SystemExit("OAuthAccessTokenService helper anchor missing")
access = access.replace(anchor, helpers, 1)
old_body = """        if (!hash_equals($authorization->subject, $subject) || !hash_equals($authorization->clientId, $clientId)) {
            return false;
        }
        foreach ($audiences as $audience) {
            if (!in_array($audience, $authorization->audiences, true)) {
                return false;
            }
        }
        foreach ($scopes as $scope) {
            if (!in_array($scope, $authorization->scopes, true)) {
                return false;
            }
        }

        return true;"""
new_body = """        return hash_equals($authorization->subject, $subject)
            && hash_equals($authorization->clientId, $clientId)
            && array_all($audiences, static fn(string $audience): bool => in_array($audience, $authorization->audiences, true))
            && array_all($scopes, static fn(string $scope): bool => in_array($scope, $authorization->scopes, true));"""
if old_body not in access:
    raise SystemExit("OAuthAccessTokenService authorizationAllows body missing")
access_path.write_text(access.replace(old_body, new_body, 1))

# Client assertion complexity: split structural/temporal validation.
assertion_path = Path("src/Auth/OAuth/OAuthClientAssertionValidator.php")
assertion = assertion_path.read_text()
start = assertion.index("    /** @param array<string, mixed> $claims */\n    private function validateClaims")
end = assertion.index("    private function audienceMatches", start)
replacement = """    /** @param array<string, mixed> $claims */
    private function validateClaims(array $claims, string $clientId, string $audience): OAuthClientAssertionStatus
    {
        if (count($claims) > AuthProtocolPolicy::MAX_AUTH_CLAIMS
            || !self::hasRequiredClaims($claims)
            || !$this->validCoreClaims($claims, $clientId, $audience)) {
            return OAuthClientAssertionStatus::INVALID_CLAIMS;
        }

        return $this->temporalStatus($claims);
    }

    /** @param array<string, mixed> $claims */
    private static function hasRequiredClaims(array $claims): bool
    {
        return array_all(
            ['iss', 'sub', 'aud', 'exp', 'iat', 'jti'],
            static fn(string $claim): bool => array_key_exists($claim, $claims),
        );
    }

    /** @param array<string, mixed> $claims */
    private function validCoreClaims(array $claims, string $clientId, string $audience): bool
    {
        return is_string($claims['iss'])
            && is_string($claims['sub'])
            && hash_equals($clientId, $claims['iss'])
            && hash_equals($clientId, $claims['sub'])
            && is_int($claims['exp'])
            && is_int($claims['iat'])
            && is_string($claims['jti'])
            && AuthProtocolPolicy::validText($claims['jti'], self::MAX_JTI_BYTES)
            && $this->audienceMatches($claims['aud'], $audience)
            && (!array_key_exists('nbf', $claims) || is_int($claims['nbf']));
    }

    /** @param array<string, mixed> $claims */
    private function temporalStatus(array $claims): OAuthClientAssertionStatus
    {
        $issuedAt = $claims['iat'];
        $expiresAt = $claims['exp'];
        $notBefore = $claims['nbf'] ?? null;
        if (!is_int($issuedAt) || !is_int($expiresAt)) {
            return OAuthClientAssertionStatus::INVALID_CLAIMS;
        }
        if ($issuedAt < 1
            || $expiresAt <= $issuedAt
            || ($expiresAt - $issuedAt) > $this->maximumLifetimeSeconds
            || (is_int($notBefore) && $notBefore >= $expiresAt)) {
            return OAuthClientAssertionStatus::INVALID_CLAIMS;
        }

        $now = $this->clock->now()->getTimestamp();
        if ($issuedAt > ($now + $this->maximumFutureIssuedAtSeconds)
            || (is_int($notBefore) && $now < ($notBefore - $this->leewaySeconds))) {
            return OAuthClientAssertionStatus::NOT_YET_VALID;
        }

        return $now >= ($expiresAt + $this->leewaySeconds)
            ? OAuthClientAssertionStatus::EXPIRED
            : OAuthClientAssertionStatus::VALID;
    }

"""
assertion_path.write_text(assertion[:start] + replacement + assertion[end:])

# Refresh rotation complexity: isolate successor scope and artifact issue decisions.
refresh_path = Path("src/Auth/OAuth/RefreshTokenManager.php")
refresh = refresh_path.read_text()
rotate_start = refresh.index("    /** @param null|array<array-key, mixed> $requestedScopes */\n    public function rotate")
rotate_end = refresh.rindex("\n}")
rotate_replacement = """    /** @param null|array<array-key, mixed> $requestedScopes */
    public function rotate(
        #[\\SensitiveParameter]
        string $token,
        string $clientId,
        ?string $dpopKeyThumbprint = null,
        int $idleLifetimeSeconds = RefreshTokenArtifact::DEFAULT_IDLE_LIFETIME_SECONDS,
        ?array $requestedScopes = null,
    ): RefreshTokenRotationResult {
        AuthProtocolPolicy::assertText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Refresh-token client ID');
        if ($dpopKeyThumbprint !== null && !RefreshTokenGrant::validDpopKeyThumbprint($dpopKeyThumbprint)) {
            throw new ConfigurationException('Refresh-token DPoP key thumbprint must be a SHA-256 Base64URL value.');
        }

        try {
            $current = RefreshTokenRecord::fromClaims($this->artifact->decryptForStateResolution($token));
        } catch (InvalidTokenException) {
            return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::INVALID);
        }

        $successor = $this->successorGrant($current, $requestedScopes);
        if ($successor instanceof RefreshTokenRotationResult) {
            return $successor;
        }
        if ($this->expired($current)) {
            return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::EXPIRED);
        }

        for ($attempt = 0; $attempt < self::STORAGE_ATTEMPTS; $attempt++) {
            $issue = $this->successorIssue($current, $successor, $idleLifetimeSeconds);
            if ($issue instanceof RefreshTokenRotationResult) {
                return $issue;
            }

            $replacement = RefreshTokenRecord::fromClaims($issue->claims);
            $status = $this->store->rotate(
                $current,
                $replacement,
                $clientId,
                $dpopKeyThumbprint,
                $replacement->issuedAt,
            );
            if ($status === RefreshTokenRotationStatus::ROTATED) {
                return RefreshTokenRotationResult::success($issue->token, $successor);
            }
            if ($status !== RefreshTokenRotationStatus::CONFLICT) {
                return RefreshTokenRotationResult::failure($status);
            }
        }

        return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::CONFLICT);
    }

    /** @param null|array<array-key, mixed> $requestedScopes */
    private function successorGrant(
        RefreshTokenRecord $current,
        ?array $requestedScopes,
    ): RefreshTokenGrant|RefreshTokenRotationResult {
        if ($requestedScopes === null) {
            return $current->grant;
        }

        try {
            return $current->grant->withScopes($requestedScopes);
        } catch (ConfigurationException) {
            return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::SCOPE_MISMATCH);
        }
    }

    private function successorIssue(
        RefreshTokenRecord $current,
        RefreshTokenGrant $grant,
        int $idleLifetimeSeconds,
    ): RefreshTokenArtifactIssue|RefreshTokenRotationResult {
        try {
            return $this->artifact->issue(
                $grant,
                familyId: $current->familyId,
                idleLifetimeSeconds: $idleLifetimeSeconds,
            );
        } catch (ConfigurationException $exception) {
            if ($this->expired($current)) {
                return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::EXPIRED);
            }

            throw $exception;
        }
    }

    private function expired(RefreshTokenRecord $record): bool
    {
        return $this->clock->now()->getTimestamp() >= $record->grant->expiresAt;
    }
"""
refresh_path.write_text(refresh[:rotate_start] + rotate_replacement + refresh[rotate_end:])
