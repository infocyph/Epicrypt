<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Enum;

enum CertificatePurpose: int
{
    case SSL_CLIENT = X509_PURPOSE_SSL_CLIENT;

    case SSL_SERVER = X509_PURPOSE_SSL_SERVER;
}
