<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\Token\SignatureEncodingException;

final class EcdsaSignatureConverter
{
    public function fromAsn1(string $signature, int $length): string
    {
        if ($length < 2 || $length % 2 !== 0) {
            throw new SignatureEncodingException('Invalid JOSE signature width.');
        }

        $offset = 0;
        if ($this->readByte($signature, $offset) !== 0x30) {
            throw new SignatureEncodingException('ECDSA signature must contain one DER sequence.');
        }

        $sequenceLength = $this->readLength($signature, $offset);
        if ($sequenceLength !== strlen($signature) - $offset) {
            throw new SignatureEncodingException('ECDSA DER sequence length is invalid.');
        }

        $coordinateWidth = intdiv($length, 2);
        $r = $this->readPositiveInteger($signature, $offset, $coordinateWidth);
        $s = $this->readPositiveInteger($signature, $offset, $coordinateWidth);
        if ($offset !== strlen($signature)) {
            throw new SignatureEncodingException('ECDSA DER signature contains trailing data.');
        }

        return str_pad($r, $coordinateWidth, "\0", STR_PAD_LEFT)
            . str_pad($s, $coordinateWidth, "\0", STR_PAD_LEFT);
    }

    public function toAsn1(string $signature, int $length): string
    {
        if ($length < 2 || $length % 2 !== 0 || strlen($signature) !== $length) {
            throw new SignatureEncodingException('Invalid signature length.');
        }

        $coordinateWidth = intdiv($length, 2);
        $r = $this->encodePositiveInteger(substr($signature, 0, $coordinateWidth));
        $s = $this->encodePositiveInteger(substr($signature, $coordinateWidth));
        $body = "\x02" . $this->encodeLength(strlen($r)) . $r
            . "\x02" . $this->encodeLength(strlen($s)) . $s;

        return "\x30" . $this->encodeLength(strlen($body)) . $body;
    }

    private function encodeLength(int $length): string
    {
        if ($length < 0 || $length > 0xffff) {
            throw new SignatureEncodingException('ECDSA DER length encoding is unsupported.');
        }
        if ($length < 0x80) {
            return chr($length);
        }
        if ($length <= 0xff) {
            return "\x81" . chr($length);
        }

        return "\x82" . pack('n', $length);
    }

    private function encodePositiveInteger(string $coordinate): string
    {
        $coordinate = ltrim($coordinate, "\0");
        if ($coordinate === '') {
            $coordinate = "\0";
        }
        if ((ord($coordinate[0]) & 0x80) !== 0) {
            return "\0" . $coordinate;
        }

        return $coordinate;
    }

    private function readByte(string $data, int &$offset): int
    {
        if (!isset($data[$offset])) {
            throw new SignatureEncodingException('ECDSA DER signature is truncated.');
        }

        return ord($data[$offset++]);
    }

    private function readLength(string $data, int &$offset): int
    {
        $first = $this->readByte($data, $offset);
        if ($first < 0x80) {
            return $first;
        }

        $octets = $first & 0x7f;
        if ($octets < 1 || $octets > 2) {
            throw new SignatureEncodingException('ECDSA DER length encoding is unsupported.');
        }

        $length = 0;
        for ($index = 0; $index < $octets; $index++) {
            $next = $this->readByte($data, $offset);
            if ($index === 0 && $next === 0) {
                throw new SignatureEncodingException('ECDSA DER length is not minimally encoded.');
            }
            $length = ($length << 8) | $next;
        }
        if ($length < 0x80 || ($octets === 2 && $length <= 0xff)) {
            throw new SignatureEncodingException('ECDSA DER length is not minimally encoded.');
        }

        return $length;
    }

    private function readPositiveInteger(string $data, int &$offset, int $coordinateWidth): string
    {
        if ($this->readByte($data, $offset) !== 0x02) {
            throw new SignatureEncodingException('ECDSA DER sequence must contain exactly two integers.');
        }

        $length = $this->readLength($data, $offset);
        if ($length < 1 || $length > strlen($data) - $offset) {
            throw new SignatureEncodingException('ECDSA DER integer length is invalid.');
        }

        $integer = substr($data, $offset, $length);
        $offset += $length;
        $first = ord($integer[0]);
        if (($first & 0x80) !== 0) {
            throw new SignatureEncodingException('ECDSA DER integers must be positive.');
        }
        if ($first === 0 && $length > 1) {
            if ((ord($integer[1]) & 0x80) === 0) {
                throw new SignatureEncodingException('ECDSA DER integer is not minimally encoded.');
            }
            $integer = substr($integer, 1);
        }
        if ($integer === '' || trim($integer, "\0") === '') {
            throw new SignatureEncodingException('ECDSA DER integers must be greater than zero.');
        }
        if (strlen($integer) > $coordinateWidth) {
            throw new SignatureEncodingException('ECDSA DER integer exceeds the selected curve width.');
        }

        return $integer;
    }
}
