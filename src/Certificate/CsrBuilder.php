<?php

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Contract\CsrBuilderInterface;

final readonly class CsrBuilder implements CsrBuilderInterface
{
    public function __construct(
        private CsrBuilderInterface $backend,
    ) {}

    public static function openSsl(): self
    {
        return new self(new OpenSSL\CsrBuilder());
    }

    /**
     * @param  array<string, string>  $distinguishedName
     */
    public function build(array $distinguishedName, string $privateKey, ?string $passphrase = null): string
    {
        return $this->backend->build($distinguishedName, $privateKey, $passphrase);
    }
}
