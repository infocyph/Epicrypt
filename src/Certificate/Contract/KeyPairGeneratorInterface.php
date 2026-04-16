<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Contract;

interface KeyPairGeneratorInterface
{
    /**
     * @return array{private: string, public: string}
     */
    public function generate(?string $passphrase = null, bool $asBase64Url = false): array;
}
