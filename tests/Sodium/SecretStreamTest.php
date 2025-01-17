<?php

use Infocyph\Epicrypt\Sodium\SodiumSecretStream;
use Infocyph\Pathwise\Exceptions\FileAccessException;

// Set up temporary paths for testing
beforeEach(function () {
    $this->key = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
    $this->inputPath = sys_get_temp_dir() . '/input.txt';
    $this->encryptedPath = sys_get_temp_dir() . '/encrypted.txt';
    $this->decryptedPath = sys_get_temp_dir() . '/decrypted.txt';

    // Write sample input data
    file_put_contents($this->inputPath, 'This is a test file for encryption and decryption.');
});

// Clean up temporary files
afterEach(function () {
//    @unlink($this->inputPath);
//    @unlink($this->encryptedPath);
//    @unlink($this->decryptedPath);
});

it('encrypts and decrypts using xchacha20poly1305', function () {
    $stream = new SodiumSecretStream($this->key, 'xchacha20poly1305');

    // Encrypt the file
    $chunkSize = 8192;
    $writtenBytes = $stream->encrypt($this->inputPath, $this->encryptedPath, $chunkSize);
    expect($writtenBytes)->toBeGreaterThan(0);

    // Ensure the encrypted file exists
    expect(file_exists($this->encryptedPath))->toBeTrue();

    // Decrypt the file
    $stream->decrypt($this->encryptedPath, $this->decryptedPath, $chunkSize);

    // Validate the decrypted content matches the original
    $originalContent = file_get_contents($this->inputPath);
    $decryptedContent = file_get_contents($this->decryptedPath);
    expect($decryptedContent)->toEqual($originalContent);
});

it('encrypts and decrypts using xchacha20', function () {
    $stream = new SodiumSecretStream($this->key, 'xchacha20');

    // Encrypt the file
    $chunkSize = 8192;
    $writtenBytes = $stream->encrypt($this->inputPath, $this->encryptedPath, $chunkSize);
    expect($writtenBytes)->toBeGreaterThan(0);

    // Ensure the encrypted file exists
    expect(file_exists($this->encryptedPath))->toBeTrue();

    // Decrypt the file
    $stream->decrypt($this->encryptedPath, $this->decryptedPath, $chunkSize);

    // Validate the decrypted content matches the original
    $originalContent = file_get_contents($this->inputPath);
    $decryptedContent = file_get_contents($this->decryptedPath);
    expect($decryptedContent)->toEqual($originalContent);
});

it('throws an exception for unsupported algorithm', function () {
    new SodiumSecretStream($this->key, 'unsupported_algorithm');
})->throws(InvalidArgumentException::class);

it('throws an exception when input file does not exist', function () {
    $stream = new SodiumSecretStream($this->key, 'xchacha20poly1305');
    $stream->encrypt('/nonexistent/file.txt', $this->encryptedPath);
})->throws(\Infocyph\Epicrypt\Exceptions\FileAccessException::class);


it('throws an exception for corrupted xchacha20poly1305 file', function () {
    $stream = new SodiumSecretStream($this->key, 'xchacha20poly1305');

    // Create a corrupted file with insufficient header bytes
    file_put_contents($this->encryptedPath, random_bytes(10));

    // Attempt decryption
    $stream->decrypt($this->encryptedPath, $this->decryptedPath);
})->throws(SodiumException::class);

