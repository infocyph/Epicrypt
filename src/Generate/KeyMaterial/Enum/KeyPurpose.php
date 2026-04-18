<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial\Enum;

enum KeyPurpose: string
{
    case AEAD = 'aead';

    case MAC = 'mac';

    case MASTER_SECRET = 'master_secret';

    case SECRETBOX = 'secretbox';

    case SECRETSTREAM = 'secretstream';

    case SIGNED_PAYLOAD = 'signed_payload';

    case TOKEN_SIGNING = 'token_signing';

    case WRAPPED_SECRET_MASTER = 'wrapped_secret_master';
}
