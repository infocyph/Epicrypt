Testing and Quality
===================

Epicrypt ships with a multi-layer quality pipeline.

Main Commands
-------------

.. code-block:: bash

   composer test:syntax
   composer test:code
   composer test:lint
   composer test:sniff
   composer test:static
   composer test:security
   composer test:refactor
   composer tests

``composer tests`` runs the full ``test:all`` sequence.

Coverage
--------

Configuration is present in ``phpunit.xml`` / ``pest.xml``, but coverage requires a driver.

Run Coverage
~~~~~~~~~~~~

.. code-block:: bash

   vendor/bin/pest --coverage

If you see ``No code coverage driver is available``, enable one of:

- ``xdebug``
- ``pcov``

Examples:

.. code-block:: bash

   php -d xdebug.mode=coverage vendor/bin/pest --coverage
   # or
   php -d pcov.enabled=1 vendor/bin/pest --coverage

Static and Security Analysis
----------------------------

- PHPStan: ``composer test:static``
- Psalm security mode: ``composer test:security``

Refactor Safety
---------------

- Rector dry-run: ``composer test:refactor``
