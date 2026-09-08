<?php

declare(strict_types=1);

it('keeps Pathwise outside the Epicrypt production dependency graph', function () {
    $composer = json_decode(file_get_contents(dirname(__DIR__, 2) . '/composer.json'), true, flags: JSON_THROW_ON_ERROR);

    expect($composer['require'])->not->toHaveKey('infocyph/pathwise')
        ->and($composer['require-dev']['infocyph/pathwise'] ?? null)->toBe('^4.0');
});

it('contains no production Pathwise imports or fully-qualified references', function () {
    $root = dirname(__DIR__, 2) . '/src';
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
    $violations = [];

    foreach ($iterator as $file) {
        if (!$file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }
        $contents = file_get_contents($file->getPathname());
        if (is_string($contents) && str_contains($contents, 'Infocyph\\Pathwise\\')) {
            $violations[] = substr($file->getPathname(), strlen(dirname(__DIR__, 2)) + 1);
        }
    }

    expect($violations)->toBe([]);
});
