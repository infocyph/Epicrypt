<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\FileAccessException;

/** @internal */
final class StreamIO
{
    public static function assertDistinctLocalPaths(string $inputPath, string $outputPath): void
    {
        self::assertLocalPath($inputPath);
        self::assertLocalPath($outputPath);

        if (!is_file($inputPath) || !is_readable($inputPath)) {
            throw new FileAccessException('Input file is not readable: ' . $inputPath);
        }

        $inputRealPath = realpath($inputPath);
        $outputRealPath = realpath($outputPath);
        if ($inputRealPath !== false && $outputRealPath !== false && $inputRealPath === $outputRealPath) {
            throw new FileAccessException('Input and output must identify different files.');
        }

        if ($inputRealPath !== false && $outputRealPath === false) {
            $outputDirectory = realpath(dirname($outputPath));
            if ($outputDirectory !== false
                && $outputDirectory . DIRECTORY_SEPARATOR . basename($outputPath) === $inputRealPath) {
                throw new FileAccessException('Input and output must identify different files.');
            }
        }
    }

    public static function assertLocalPath(string $path): void
    {
        if ($path === '' || str_contains($path, "\0")) {
            throw new FileAccessException('Local file path must be non-empty and NUL-free.');
        }

        if (preg_match('/\A[A-Za-z][A-Za-z0-9+.-]*:\/\//D', $path) === 1) {
            throw new FileAccessException('Epicrypt local path APIs do not accept stream-wrapper or storage schemes.');
        }
    }

    /** @param resource $stream */
    public static function assertReadable(mixed $stream, string $label = 'Input stream'): void
    {
        $mode = self::mode($stream, $label);
        if ($mode[0] !== 'r' && !str_contains($mode, '+')) {
            throw new FileAccessException($label . ' is not readable.');
        }
    }

    /** @param resource $stream */
    public static function assertWritable(mixed $stream, string $label = 'Output stream'): void
    {
        $mode = self::mode($stream, $label);
        if (!in_array($mode[0], ['w', 'a', 'x', 'c'], true) && !str_contains($mode, '+')) {
            throw new FileAccessException($label . ' is not writable.');
        }
    }

    /** @param resource $stream */
    public static function readChunk(mixed $stream, int $maximumBytes): ?string
    {
        self::assertReadable($stream);
        if ($maximumBytes < 1) {
            throw new \InvalidArgumentException('Maximum read size must be positive.');
        }

        if (feof($stream)) {
            return null;
        }

        $buffer = '';
        while (strlen($buffer) < $maximumBytes && !feof($stream)) {
            $chunk = fread($stream, $maximumBytes - strlen($buffer));
            if ($chunk === false) {
                throw new FileAccessException('Unable to read from input stream.');
            }

            if ($chunk === '') {
                if (feof($stream)) {
                    break;
                }

                throw new FileAccessException('Input stream made no progress before EOF.');
            }
            $buffer .= $chunk;
        }

        return $buffer === '' && feof($stream) ? null : $buffer;
    }

    /** @param resource $stream */
    public static function readLine(mixed $stream, int $maximumBytes): string
    {
        self::assertReadable($stream);
        if ($maximumBytes < 1) {
            throw new \InvalidArgumentException('Maximum line size must be positive.');
        }

        $line = '';
        while (strlen($line) <= $maximumBytes) {
            $byte = fread($stream, 1);
            if ($byte === false) {
                throw new FileAccessException('Unable to read from input stream.');
            }

            if ($byte === '') {
                if (feof($stream)) {
                    throw new FileAccessException('Input stream ended before the required line terminator.');
                }

                throw new FileAccessException('Input stream made no progress before EOF.');
            }

            if ($byte === "\n") {
                return $line;
            }
            $line .= $byte;
        }

        throw new FileAccessException('Input stream line exceeds the configured size bound.');
    }

    /**
     * @template TResult
     * @param \Closure(resource): TResult $operation
     * @return TResult
     */
    public static function withAtomicLocalOutput(string $outputPath, \Closure $operation): mixed
    {
        self::assertLocalPath($outputPath);
        $directory = dirname($outputPath);
        if (!is_dir($directory) || !is_writable($directory)) {
            throw new FileAccessException('Output directory is not writable: ' . $directory);
        }

        if (file_exists($outputPath) && !is_file($outputPath) && !is_link($outputPath)) {
            throw new FileAccessException('Output path is not a regular file target: ' . $outputPath);
        }

        $temporaryPath = tempnam($directory, '.epicrypt-');
        if ($temporaryPath === false) {
            throw new FileAccessException('Unable to create a temporary output file.');
        }

        if (!chmod($temporaryPath, 0600)) {
            self::removeTemporaryFile($temporaryPath);

            throw new FileAccessException('Unable to secure the temporary output file.');
        }

        $stream = fopen($temporaryPath, 'wb');
        if (!is_resource($stream)) {
            self::removeTemporaryFile($temporaryPath);

            throw new FileAccessException('Unable to open the temporary output file.');
        }

        $committed = false;
        try {
            $result = $operation($stream);
            if (!fflush($stream)) {
                throw new FileAccessException('Unable to flush the complete output file.');
            }
            fclose($stream);
            $stream = null;
            self::replaceLocalOutput($temporaryPath, $outputPath);
            $committed = true;

            return $result;
        } finally {
            if (is_resource($stream)) {
                fclose($stream);
            }

            if (!$committed) {
                self::removeTemporaryFile($temporaryPath);
            }
        }
    }

    /**
     * @template TResult
     * @param \Closure(resource): TResult $operation
     * @return TResult
     */
    public static function withReadableLocalFile(string $path, \Closure $operation): mixed
    {
        self::assertLocalPath($path);
        if (!is_file($path) || !is_readable($path)) {
            throw new FileAccessException('Input file is not readable: ' . $path);
        }

        $stream = fopen($path, 'rb');
        if (!is_resource($stream)) {
            throw new FileAccessException('Unable to open input file: ' . $path);
        }

        $locked = false;
        try {
            $locked = flock($stream, LOCK_SH);
            if (!$locked) {
                throw new FileAccessException('Unable to acquire a shared input lock: ' . $path);
            }

            return $operation($stream);
        } finally {
            if ($locked) {
                flock($stream, LOCK_UN);
            }
            fclose($stream);
        }
    }

    /** @param resource $stream */
    public static function writeAll(mixed $stream, #[\SensitiveParameter] string $data): int
    {
        self::assertWritable($stream);
        $length = strlen($data);
        $offset = 0;

        while ($offset < $length) {
            $written = fwrite($stream, substr($data, $offset));
            if ($written === false || $written < 1) {
                throw new FileAccessException('Unable to write the complete output stream.');
            }
            $offset += $written;
        }

        return $length;
    }

    private static function mode(mixed $stream, string $label): string
    {
        if (!is_resource($stream) || get_resource_type($stream) !== 'stream') {
            throw new FileAccessException($label . ' must be an open PHP stream resource.');
        }

        $metadata = stream_get_meta_data($stream);
        $mode = $metadata['mode'] ?? '';
        if ($mode === '') {
            throw new FileAccessException($label . ' mode is unavailable.');
        }

        return $mode;
    }

    private static function removeTemporaryFile(string $path): void
    {
        if (is_file($path) && !unlink($path) && is_file($path)) {
            throw new FileAccessException('Unable to remove temporary output file.');
        }
    }

    private static function replaceLocalOutput(string $temporaryPath, string $outputPath): void
    {
        if (!file_exists($outputPath) || PHP_OS_FAMILY !== 'Windows') {
            if (!rename($temporaryPath, $outputPath)) {
                throw new FileAccessException('Unable to finalize output file: ' . $outputPath);
            }

            return;
        }

        if (!is_file($outputPath)) {
            throw new FileAccessException('Output path is not a file: ' . $outputPath);
        }

        $backupPath = $temporaryPath . '.backup';
        if (!rename($outputPath, $backupPath)) {
            throw new FileAccessException('Unable to preserve the existing output file.');
        }

        if (rename($temporaryPath, $outputPath)) {
            if (!unlink($backupPath) && is_file($backupPath)) {
                throw new FileAccessException('Unable to remove the replaced output backup.');
            }

            return;
        }

        if (!rename($backupPath, $outputPath)) {
            throw new FileAccessException('Unable to restore the existing output file.');
        }

        throw new FileAccessException('Unable to finalize output file: ' . $outputPath);
    }
}
