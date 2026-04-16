<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\Enum\SecurityTokenPurpose;

final readonly class ActionToken
{
    private SignedPayloadCodec $codec;

    public function __construct(
        string $secret,
        private int $ttlSeconds = 900,
    ) {
        $this->codec = new SignedPayloadCodec($secret);
    }

    /**
     * @param array<string, scalar> $context
     */
    public function issue(string $subject, string $action, array $context = []): string
    {
        $purpose = SecurityTokenPurpose::ACTION_TOKEN->value;

        return $this->codec->issue([
            'sub' => $subject,
            'action' => $action,
            'ctx' => $context,
            'purpose' => $purpose,
        ], time() + $this->ttlSeconds, $purpose);
    }

    public function verify(string $token, ?string $subject = null, ?string $action = null): bool
    {
        try {
            $purpose = SecurityTokenPurpose::ACTION_TOKEN->value;
            $claims = $this->codec->verify($token, $purpose);
            if (($claims['purpose'] ?? null) !== $purpose) {
                return false;
            }

            if ($subject !== null && (!isset($claims['sub']) || !is_string($claims['sub']) || !hash_equals($claims['sub'], $subject))) {
                return false;
            }

            if ($action !== null && (!isset($claims['action']) || !is_string($claims['action']) || !hash_equals($claims['action'], $action))) {
                return false;
            }

            return true;
        } catch (TokenException) {
            return false;
        }
    }
}
