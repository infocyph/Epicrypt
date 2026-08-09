<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;

final class Ristretto255
{
    public function add(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_add($this->point($left), $this->point($right));
    }

    public function fromHash(string $uniformHash): string
    {
        if (strlen($uniformHash) !== SODIUM_CRYPTO_CORE_RISTRETTO255_HASHBYTES) {
            throw new InvalidKeyException('Ristretto255 uniform hash input must contain exactly 64 bytes.');
        }

        return sodium_crypto_core_ristretto255_from_hash($uniformHash);
    }

    public function isValidPoint(string $point): bool
    {
        return strlen($point) === SODIUM_CRYPTO_CORE_RISTRETTO255_BYTES
            && sodium_crypto_core_ristretto255_is_valid_point($point);
    }

    public function multiply(string $scalar, string $point): string
    {
        return sodium_crypto_scalarmult_ristretto255($this->scalar($scalar), $this->point($point));
    }

    public function multiplyBase(string $scalar): string
    {
        return sodium_crypto_scalarmult_ristretto255_base($this->scalar($scalar));
    }

    public function randomPoint(): string
    {
        return sodium_crypto_core_ristretto255_random();
    }

    public function randomScalar(): string
    {
        return sodium_crypto_core_ristretto255_scalar_random();
    }

    public function reduceScalar(string $nonReducedScalar): string
    {
        if (strlen($nonReducedScalar) !== SODIUM_CRYPTO_CORE_RISTRETTO255_NONREDUCEDSCALARBYTES) {
            throw new InvalidKeyException('Non-reduced Ristretto255 scalar must contain exactly 64 bytes.');
        }

        return sodium_crypto_core_ristretto255_scalar_reduce($nonReducedScalar);
    }

    public function scalarAdd(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_scalar_add($this->scalar($left), $this->scalar($right));
    }

    public function scalarComplement(string $scalar): string
    {
        return sodium_crypto_core_ristretto255_scalar_complement($this->scalar($scalar));
    }

    public function scalarInvert(string $scalar): string
    {
        return sodium_crypto_core_ristretto255_scalar_invert($this->scalar($scalar));
    }

    public function scalarMultiply(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_scalar_mul($this->scalar($left), $this->scalar($right));
    }

    public function scalarNegate(string $scalar): string
    {
        return sodium_crypto_core_ristretto255_scalar_negate($this->scalar($scalar));
    }

    public function scalarSubtract(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_scalar_sub($this->scalar($left), $this->scalar($right));
    }

    public function subtract(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_sub($this->point($left), $this->point($right));
    }

    private function point(string $point): string
    {
        if (!$this->isValidPoint($point)) {
            throw new InvalidKeyException('Ristretto255 point is invalid.');
        }

        return $point;
    }

    private function scalar(string $scalar): string
    {
        if (strlen($scalar) !== SODIUM_CRYPTO_CORE_RISTRETTO255_SCALARBYTES) {
            throw new InvalidKeyException('Ristretto255 scalar must contain exactly 32 bytes.');
        }

        return $scalar;
    }
}
