<?php

namespace Infocyph\Epicrypt\Internal;

final class SecurityPolicy
{
    public const string DEFAULT_AEAD_ALGORITHM = 'xchacha20-poly1305-ietf';

    public const string DEFAULT_JWT_ASYMMETRIC_ALGORITHM = 'RS512';

    public const string DEFAULT_JWT_SYMMETRIC_ALGORITHM = 'HS512';

    public const string DEFAULT_KEY_ROTATION_HMAC_ALGORITHM = 'sha256';

    public const string DEFAULT_SIGNED_PAYLOAD_ALGORITHM = 'sha512';

    public const string ENCRYPTED_PAYLOAD_VERSION = 'epc1';

    public const string ENVELOPE_ALGORITHM = 'secretbox';

    public const int ENVELOPE_FORMAT_VERSION = 1;

    public const int PASSWORD_DEFAULT_MEMORY_COST = PASSWORD_ARGON2_DEFAULT_MEMORY_COST;

    public const int PASSWORD_DEFAULT_THREADS = PASSWORD_ARGON2_DEFAULT_THREADS;

    public const int PASSWORD_DEFAULT_TIME_COST = PASSWORD_ARGON2_DEFAULT_TIME_COST;

    public const int SIGNED_PAYLOAD_FORMAT_VERSION = 1;

    public const int SIGNED_URL_FORMAT_VERSION = 1;

    public const string SIGNED_URL_VERSION_PARAM = 'ep_v';

    public const string WRAPPED_SECRET_VERSION = 'eps1';
}
