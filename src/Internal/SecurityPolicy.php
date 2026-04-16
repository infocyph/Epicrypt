<?php

namespace Infocyph\Epicrypt\Internal;

final class SecurityPolicy
{
    public const string DEFAULT_KEY_ROTATION_HMAC_ALGORITHM = 'sha256';

    public const int PASSWORD_DEFAULT_MEMORY_COST = PASSWORD_ARGON2_DEFAULT_MEMORY_COST;

    public const int PASSWORD_DEFAULT_THREADS = PASSWORD_ARGON2_DEFAULT_THREADS;

    public const int PASSWORD_DEFAULT_TIME_COST = PASSWORD_ARGON2_DEFAULT_TIME_COST;

    public const string SIGNED_URL_VERSION_PARAM = 'ep_v';
}
