<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Enum;

enum KeyUsage: string
{
    case CRL_SIGN = 'cRLSign';

    case DATA_ENCIPHERMENT = 'dataEncipherment';

    case DECIPHER_ONLY = 'decipherOnly';

    case DIGITAL_SIGNATURE = 'digitalSignature';

    case ENCIPHER_ONLY = 'encipherOnly';

    case KEY_AGREEMENT = 'keyAgreement';

    case KEY_CERT_SIGN = 'keyCertSign';

    case KEY_ENCIPHERMENT = 'keyEncipherment';

    case NON_REPUDIATION = 'nonRepudiation';
}
