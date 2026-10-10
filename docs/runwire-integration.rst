Runwire integration
===================

Epicrypt 3.2 optionally borrows an existing Runwire 2.1.1 execution context
to check cancellation and deadlines during lengthy streaming operations.
Without Runwire installed or without an explicit context, all existing crypto,
file and remote JOSE paths remain ordinary synchronous PHP operations.

Installation and ownership
--------------------------

Only callers opting into this integration install infocyph/runwire 2.1.1.
The host owns the runtime, request and optional active coroutine scope.
Epicrypt never starts or stops the runtime, creates workers, owns a task
or completes a caller-owned request.

Bind the host objects and pass the same context across intermediaries:

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Integration\Runwire\RunwireExecutionContext;
   use Infocyph\Epicrypt\DataProtection\FileProtector;
   use Infocyph\Epicrypt\DataProtection\ProtectionOptions;

   // The host supplies $runtime, $request, $scope and caller-owned streams.
   $context = new RunwireExecutionContext($runtime, $request, $scope);
   $metadata = (new FileProtector())->protectStream(
       $input, $output, $base64UrlKey,
       new ProtectionOptions('archive/v1'),
       context: $context,
   );

The optional named context argument is available on SecretStream encrypt
and decrypt methods (file and stream), FileProtector variants, FileHasher
hash and verify methods (file and stream), RemoteJwks::load and resolve.
Do not store a per-request context on static or globally shared owners.

Cancellation and coroutine scheduling
-------------------------------------

A borrowed context checks its PID, request/runtime identity, completion,
request cancellation/deadline and a task-local binding to the live host scope.
Construct the binding inside the owning scope/task, then forward it only
within that task or intentionally inherited child work; unrelated or previously
started sibling tasks must not reuse the binding.
Task-local binding snapshots hold weak references, so discarding contexts
does not accumulate markers inside a long-lived task. Creating a new binding
copies the snapshot without changing bindings visible to existing siblings.
checkpointEvery defaults to 256 and is bounded to 1-1000000. A live
CoroutineScope and the RUNWIRE_COROUTINES capability are both necessary
for cooperative yieldNow; capability alone does not create a scheduler.
Without a scope, cancellation still works without coroutine operations.

Local-file paths preserve existing atomic staging and publication cleanup.
The host's cancellation state is checked again after a staged write and before
atomic replacement, so cancellation does not publish a completed staging file.
When cancelled, an existing destination remains intact. Caller-owned
output streams may contain partial data: the host owns their publication.
Remote JWKS cancellation from HTTP or cache operations is propagated and
is not converted into a stale cached key result. Stale expiry is checked
after a failed refresh, including time spent waiting for the transport.
Regular file and PSR-18 network I/O remain synchronous; caller-owned
HTTP transports must still set suitable timeouts and enforce DNS pinning.

Unvalidated Runwire versions are excluded by the optional compatibility
contract until explicitly certified. No production Pathwise dependency
is introduced. See :doc:`data-protection`, :doc:`integrity`, and
:doc:`remote-jose-security` for the underlying security boundaries.
