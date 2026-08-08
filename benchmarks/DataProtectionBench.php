<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\DataProtection\EnvelopeProtector;
use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionAlgorithm;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\DataProtection\StringProtector;
use PhpBench\Attributes as Bench;

#[Bench\Revs(20)]
#[Bench\Iterations(3)]
#[Bench\Warmup(1)]
final class DataProtectionBench
{
    private string $encrypted;

    /** @var array<string, EnvelopeProtector> */
    private array $envelopes = [];

    /** @var array<string, string> */
    private array $envelopeValues = [];

    private string $fileKey;

    private FileProtector $files;

    private string $input;

    /** @var array<string, string> */
    private array $keys = [];

    private ProtectionOptions $options;

    private string $output;

    /** @var array<string, StringProtector> */
    private array $strings = [];

    /** @var array<string, string> */
    private array $stringValues = [];

    public function setUp(): void
    {
        $directory = sys_get_temp_dir() . '/epicrypt-bench';
        if (!is_dir($directory)) {
            mkdir($directory);
        }
        $this->input = $directory . '/input';
        $this->encrypted = $directory . '/encrypted';
        $this->output = $directory . '/output';
        file_put_contents($this->input, random_bytes(1024 * 1024));
        $this->fileKey = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $this->options = new ProtectionOptions('benchmark', 'fixture=v2');
        $this->files = new FileProtector();
        foreach (ProtectionAlgorithm::cases() as $algorithm) {
            if (!$algorithm->isAvailable()) {
                continue;
            }
            $id = $algorithm->value;
            $this->keys[$id] = sodium_bin2base64(
                random_bytes($algorithm->keyLength()),
                SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
            );
            $this->strings[$id] = StringProtector::create($algorithm);
            $this->envelopes[$id] = EnvelopeProtector::create($algorithm);
            $this->stringValues[$id] = $this->strings[$id]->protect(
                'benchmark payload',
                $this->keys[$id],
                $this->options,
            );
            $this->envelopeValues[$id] = $this->envelopes[$id]->protect(
                'benchmark payload',
                $this->keys[$id],
                $this->options,
            );
        }
        $this->files->protect($this->input, $this->encrypted, $this->fileKey, $this->options);
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('protectionAlgorithms')]
    public function benchEnvelopeDecrypt(array $params): void
    {
        $algorithm = $params['algorithm'];
        $this->envelopes[$algorithm]->unprotect(
            $this->envelopeValues[$algorithm],
            $this->keys[$algorithm],
            $this->options,
        );
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('protectionAlgorithms')]
    public function benchEnvelopeEncrypt(array $params): void
    {
        $algorithm = $params['algorithm'];
        $this->envelopes[$algorithm]->protect('benchmark payload', $this->keys[$algorithm], $this->options);
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('chunkSizes')]
    public function benchFileRoundtrip(array $params): void
    {
        $this->files->protect($this->input, $this->encrypted, $this->fileKey, $this->options, $params['chunk']);
        $this->files->unprotect($this->encrypted, $this->output, $this->fileKey, $this->options, $params['chunk']);
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('protectionAlgorithms')]
    public function benchStringDecrypt(array $params): void
    {
        $algorithm = $params['algorithm'];
        $this->strings[$algorithm]->unprotect(
            $this->stringValues[$algorithm],
            $this->keys[$algorithm],
            $this->options,
        );
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('protectionAlgorithms')]
    public function benchStringEncrypt(array $params): void
    {
        $algorithm = $params['algorithm'];
        $this->strings[$algorithm]->protect('benchmark payload', $this->keys[$algorithm], $this->options);
    }

    /** @return iterable<string, array{chunk: int}> */
    public function chunkSizes(): iterable
    {
        yield '64KiB' => ['chunk' => 64 * 1024];
        yield '256KiB' => ['chunk' => 256 * 1024];
        yield '1MiB' => ['chunk' => 1024 * 1024];
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function protectionAlgorithms(): iterable
    {
        foreach (ProtectionAlgorithm::cases() as $algorithm) {
            if ($algorithm->isAvailable()) {
                yield $algorithm->value => ['algorithm' => $algorithm->value];
            }
        }
    }
}
