<?php


namespace AbmmHasan\SafeGuard\Asymmetric;


use Exception;

class KeyGenerator
{
    private array $csrOption = [
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'encrypt_key' => true,
        'encrypt_key_cipher' => OPENSSL_CIPHER_AES_256_CBC,
        'curve_name' => 'prime256v1'
    ];

    private array $keyOption = [
        'digest_alg' => 'SHA512',
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'encrypt_key' => true,
        'encrypt_key_cipher' => OPENSSL_CIPHER_AES_256_CBC,
        'curve_name' => 'prime256v1'
    ];

    private array $pKeyInfo;
    private array $resource;
    private array $certificate;
    private array $settings;

    /**
     * Set certificate issuer information
     *
     * @param string $country Country name
     * @param string $province State or Province name
     * @param string $locality Locality name
     * @param string $organization Organization name
     * @param string $unit Organizational Unit name
     * @param string $name Common Name (e.g. Domain name)
     * @param string $email Email address
     */
    public function __construct(string $country, string $province, string $locality, string $organization, string $unit, string $name, string $email)
    {
        $this->settings = [
            "countryName" => $country,
            "stateOrProvinceName" => $province,
            "localityName" => $locality,
            "organizationName" => $organization,
            "organizationalUnitName" => $unit,
            "commonName" => $name,
            "emailAddress" => $email
        ];
    }

    /**
     * Set options for CSR
     *
     * @param $key
     * @param $value
     * @throws Exception
     */
    public function setCsrOptions($key, $value)
    {
        if ($key === 'config') {
            $this->setConfPath($value);
        } else {
            $this->csrOption[$key] = $value;
        }
    }

    /**
     * Set options for keys
     *
     * @param $key
     * @param $value
     * @throws Exception
     */
    public function setKeyOptions($key, $value)
    {
        if ($key === 'config') {
            $this->setConfPath($value);
        } else {
            $this->keyOption[$key] = $value;
        }
    }

    /**
     * Set openssl.conf file path
     *
     * @param string $path
     * @throws Exception
     */
    public function setConfPath(string $path)
    {
        $path = realpath($path);
        if (empty($path)) {
            throw new Exception('Invalid openssl.conf file path!');
        }
        $this->csrOption['config'] = $this->keyOption['config'] = $path;
    }

    /**
     * Set predefined pkey resource
     *
     * @param string|null $keyPair
     * @param string|null $csrResource
     */
    public function setResource(string $keyPair = null, string $csrResource = null)
    {
        $this->resource = [
            'keyPair' => $keyPair,
            'csr' => $csrResource,
        ];
    }

    /**
     * Get generated resources
     *
     * @return array
     */
    public function get(): array
    {
        return [
            'type' => $this->certificate['type'],
            'typeInt' => $this->pKeyInfo['type'],
            'bits' => $this->pKeyInfo['bits'],
            'asset' => [
                'private' => $this->certificate['private'],
                'public' => $this->certificate['public'],
                'csr' => $this->certificate['csr'],
                'certificate' => $this->certificate['certificate'] ?? false
            ],
            'details' => $this->pKeyInfo[$this->certificate['type']]
        ];
    }

    /**
     * Export generated resources to given location
     *
     * @param string $path
     * @param string $name
     * @return bool
     * @throws Exception
     */
    public function export(string $path, string $name = 'server'): bool
    {
        if (empty($this->certificate)) {
            throw new Exception('Certificate not generated!');
        }
        if (($e = openssl_error_string()) !== false) {
            throw new Exception($e);
        }
        $path = rtrim($path, '/\\') . DIRECTORY_SEPARATOR;

        // private, public key
        if (file_put_contents($path . $name . '.key', $this->certificate['private'], LOCK_EX) === false) {
            throw new Exception('File exporting failed!');
        }
        file_put_contents($path . $name . '.pub', $this->certificate['public'], LOCK_EX);

        // certificate
        file_put_contents($path . $name . '.crt', $this->certificate['certificate'], LOCK_EX);
        file_put_contents($path . $name . '.csr', $this->certificate['csr'], LOCK_EX);

        // all the details in php readable format
        file_put_contents(
            $path . $name . '.details.php',
            '<?php return ' . var_export($this->get(), true) . ';' . PHP_EOL,
            LOCK_EX
        );
        return true;
    }

    /**
     * Generate DSA resources
     *
     * @param int $daysValidFor
     * @param string|null $passphrase
     * @param string|null $certificate
     * @throws Exception
     */
    public function dsa(int $daysValidFor = 365, string $passphrase = null, string $certificate = null)
    {
        $this->csrOption['private_key_type'] = $this->keyOption['private_key_type'] = OPENSSL_KEYTYPE_DSA;
        $this->csrOption['digest_alg'] ??= 'DSA';
        $this->certificate['type'] = 'dsa';
        $this->generateKeyResource($passphrase);
        $this->generateCsr();
        $this->generateSigned($daysValidFor, $certificate);
    }

    /**
     * Generate RSA resources
     *
     * @param int $daysValidFor
     * @param null|string $passphrase
     * @param null|string $certificate
     * @throws Exception
     */
    public function rsa(int $daysValidFor = 365, string $passphrase = null, string $certificate = null)
    {
        $this->csrOption['private_key_type'] = $this->keyOption['private_key_type'] = OPENSSL_KEYTYPE_RSA;
        $this->csrOption['digest_alg'] ??= 'SHA512';
        $this->certificate['type'] = 'rsa';
        $this->generateKeyResource($passphrase);
        $this->generateCsr();
        $this->generateSigned($daysValidFor, $certificate);
    }

    /**
     * Generate EC resources
     *
     * @param int $daysValidFor
     * @param null|string $passphrase
     * @param null|string $certificate
     * @throws Exception
     */
    public function ec(int $daysValidFor = 365, string $passphrase = null, string $certificate = null)
    {
        $this->csrOption['private_key_type'] = $this->keyOption['private_key_type'] = OPENSSL_KEYTYPE_EC;
        $this->csrOption['digest_alg'] ??= 'SHA512';
        $this->certificate['type'] = 'ec';
        $this->generateKeyResource($passphrase);
        $this->generateCsr();
        $this->generateSigned($daysValidFor, $certificate);
    }

    /**
     * @param $passphrase
     * @throws Exception
     */
    private function generateKeyResource($passphrase)
    {
        if (empty(getenv('OPENSSL_CONF')) && (empty($this->csrOption['config']) || empty($this->keyOption['config']))) {
            throw new Exception('openssl.conf file not found!');
        }

        if (empty($this->resource['keyPair'])) {
            // Generate a new private (and public) key pair
            $this->resource['keyPair'] = openssl_pkey_new($this->keyOption);
        }

        $this->pKeyInfo = openssl_pkey_get_details($this->resource['keyPair']);
        $this->certificate['public'] = $this->pKeyInfo['key'];

        // Export private key
        openssl_pkey_export($this->resource['keyPair'], $this->certificate['private'], $passphrase, $this->keyOption);
    }

    private function generateCsr()
    {
        if (empty($this->resource['csr'])) {
            // Generate a Certificate Signing Request
            $this->resource['csr'] = openssl_csr_new($this->settings, $this->resource['keyPair'], $this->csrOption);
        }

        // Export CSR
        openssl_csr_export($this->resource['csr'], $this->certificate['csr']);
    }

    private function generateSigned($validFor, $certificate)
    {
        // Export (Signed for given days) Certificate
        openssl_x509_export(
            openssl_csr_sign($this->resource['csr'], $certificate, $this->resource['keyPair'], $validFor, $this->csrOption),
            $this->certificate['certificate']
        );
    }
}
