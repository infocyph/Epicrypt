<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

enum SigningKeyReadinessFailureReason: string
{
    case ACTIVE_KEY_ID_MISMATCH = 'active_key_id_mismatch';
    case ACTIVE_KEY_NOT_ELIGIBLE = 'active_key_not_eligible';
    case INVALID_ISSUER = 'invalid_issuer';
    case KEY_PAIR_MISMATCH = 'key_pair_mismatch';
    case PRIVATE_KEY_INVALID = 'private_key_invalid';
    case PUBLIC_KEY_SET_INVALID = 'public_key_set_invalid';

    public function message(): string
    {
        return match ($this) {
            self::ACTIVE_KEY_ID_MISMATCH => 'Active signing key id does not match the eligible active public key.',
            self::ACTIVE_KEY_NOT_ELIGIBLE => 'Exactly one eligible active signing public key is required.',
            self::INVALID_ISSUER => 'Signing key issuer is invalid.',
            self::KEY_PAIR_MISMATCH => 'Active private and public signing keys do not match.',
            self::PRIVATE_KEY_INVALID => 'Active private signing key is invalid for the configured algorithm.',
            self::PUBLIC_KEY_SET_INVALID => 'Signing public key set is invalid for the configured algorithm.',
        };
    }
}
