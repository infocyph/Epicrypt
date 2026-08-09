<?php

declare(strict_types=1);

it('syntax checks every complete PHP documentation example', function () {
    $documents = glob(dirname(__DIR__, 2) . '/docs/*.rst');
    if ($documents === false) {
        throw new RuntimeException('Unable to enumerate documentation files.');
    }

    $checked = 0;
    foreach ($documents as $document) {
        $contents = file_get_contents($document);
        if ($contents === false) {
            throw new RuntimeException('Unable to read ' . $document);
        }

        $lines = preg_split('/\R/', $contents);
        if ($lines === false) {
            throw new RuntimeException('Unable to split ' . $document);
        }

        $lineCount = count($lines);
        for ($line = 0; $line < $lineCount; ++$line) {
            if (trim($lines[$line]) !== '.. code-block:: php') {
                continue;
            }

            $snippet = [];
            for ($cursor = $line + 1; $cursor < $lineCount; ++$cursor) {
                $candidate = $lines[$cursor];
                if ($candidate === '' && $snippet === []) {
                    continue;
                }
                if (!str_starts_with($candidate, '   ')) {
                    break;
                }
                $snippet[] = substr($candidate, 3);
            }

            $source = rtrim(implode("\n", $snippet)) . "\n";
            if (!str_starts_with(ltrim($source), '<?php')) {
                continue;
            }

            try {
                token_get_all($source, TOKEN_PARSE);
            } catch (ParseError $error) {
                throw new RuntimeException(
                    sprintf('%s:%d contains invalid PHP: %s', $document, $line + 1, $error->getMessage()),
                    previous: $error,
                );
            }
            ++$checked;
        }
    }

    expect($checked)->toBeGreaterThanOrEqual(40);
});
