<?php

namespace AbmmHasan\SafeGuard\JWT;

trait DER
{
    private int $ASN1_INTEGER = 0x02;
    private int $ASN1_SEQUENCE = 0x10;
    private int $ASN1_BIT_STRING = 0x03;

    /**
     * Convert an ECDSA signature to an ASN.1 DER sequence
     *
     * @param string $signature The ECDSA signature to convert
     * @return  string The encoded DER object
     */
    private function fromSignature(string $signature): string
    {
        // Separate the signature into r-value and s-value
        [$r, $s] = str_split($signature, (int)(strlen($signature) / 2));

        // Trim leading zeros
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        // Unsigned big-endian integers -> Signed two's complement
        if (ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return $this->encodeDER(
            $this->ASN1_SEQUENCE,
            $this->encodeDER($this->ASN1_INTEGER, $r) .
            $this->encodeDER($this->ASN1_INTEGER, $s)
        );
    }

    /**
     * Encodes a value into a DER object.
     *
     * @param int $type DER tag
     * @param string $value the value to encode
     * @return  string  the encoded object
     */
    private function encodeDER(int $type, string $value): string
    {
        $tag_header = 0;
        if ($type === $this->ASN1_SEQUENCE) {
            $tag_header |= 0x20;
        }

        // Type . Length
        $der = chr($tag_header | $type) . chr(strlen($value));

        return $der . $value;
    }

    /**
     * Encodes signature from a DER object.
     *
     * @param string $der binary signature in DER format
     * @param int $keySize the number of bits in the key
     * @return  string  the signature
     */
    private function toSignature(string $der, int $keySize): string
    {
        // OpenSSL returns the ECDSA signatures as a binary ASN.1 DER SEQUENCE
        [$offset, $_] = $this->readDER($der);
        [$offset, $r] = $this->readDER($der, $offset);
        [$offset, $s] = $this->readDER($der, $offset);

        // Signed two's compliment -> Unsigned big-endian integers
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        // Pad out r and s so that they are $keySize bits long
        $r = str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * Reads binary DER-encoded data and decodes into a single object
     *
     * @param string $der the binary data in DER format
     * @param int $offset the offset of the data stream containing the object to decode
     * @return array [$offset, $data] the new offset and the decoded object
     */
    private function readDER(string $der, int $offset = 0): array
    {
        $pos = $offset;
        $size = strlen($der);
        $constructed = (ord($der[$pos]) >> 5) & 0x01;
        $type = ord($der[$pos++]) & 0x1f;

        // Length
        $len = ord($der[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = ($len << 8) | ord($der[$pos++]);
            }
        }

        // Value
        if ($type == $this->ASN1_BIT_STRING) {
            $pos++; // Skip the first contents octet (padding indicator)
            $data = substr($der, $pos, $len - 1);
            $pos += $len - 1;
        } elseif (!$constructed) {
            $data = substr($der, $pos, $len);
            $pos += $len;
        } else {
            $data = null;
        }

        return [$pos, $data];
    }
}
