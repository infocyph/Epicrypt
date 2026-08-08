<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

enum JwtFailureReason
{
    case ALGORITHM_MISMATCH;

    case EXPIRED;

    case INVALID_AUDIENCE;

    case INVALID_CUSTOM_CLAIM;

    case INVALID_ISSUER;

    case INVALID_JTI;

    case INVALID_LIFETIME;

    case INVALID_SIGNATURE;

    case INVALID_SUBJECT;

    case INVALID_TYPE;

    case ISSUED_IN_FUTURE;

    case KEY_NOT_USABLE;

    case MALFORMED;

    case NOT_ACTIVE;

    case REPLAYED;

    case UNKNOWN_KEY;

    case UNSUPPORTED_ALGORITHM;
}
