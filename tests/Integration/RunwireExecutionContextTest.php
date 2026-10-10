<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Integration\Runwire\RunwireExecutionContext;
use Infocyph\Runwire\Exception\CancelledException;
use Infocyph\Runwire\RequestContext;
use Infocyph\Runwire\Runtime\Enum\CancellationReason;
use Infocyph\Runwire\RuntimeContext;

it('uses only borrowed runtime objects and supports checkpoints without a scheduler', function () {
    $runtime = RuntimeContext::standalone();
    $context = new RunwireExecutionContext($runtime, checkpointEvery: 1);

    expect($context->runtime)->toBe($runtime)
        ->and($context->scope)->toBeNull()
        ->and($context->request)->toBeNull();
    $context->checkpoint();
    $context->checkpoint();
    expect($runtime->pid)->toBe(getmypid());
});

it('rejects missing lifecycle integrity, wrong PID, invalid intervals, and replaced requests', function () {
    $runtime = RuntimeContext::standalone();
    expect(fn () => new RunwireExecutionContext($runtime, checkpointEvery: 0))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new RunwireExecutionContext($runtime, checkpointEvery: 1_000_001))->toThrow(InvalidArgumentException::class);

    $otherRuntime = RuntimeContext::fromCapabilities($runtime->capabilities, 'standalone', pid: getmypid() + 1);
    expect(fn () => new RunwireExecutionContext($otherRuntime))->toThrow(LogicException::class);
    expect(fn () => new RunwireExecutionContext($runtime, RequestContext::standalone()))
        ->toThrow(LogicException::class);
});

it('rejects cancelled and completed request lifecycles without owning their termination', function () {
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $context = new RunwireExecutionContext($runtime, $request);
    $context->checkpoint();

    expect($request->completed())->toBeFalse();
    $request->cancel(CancellationReason::HOST_CANCELLED);
    expect(fn () => $context->checkpoint())->toThrow(CancelledException::class);

    $completed = RequestContext::create($runtime);
    $completed->complete();
    expect(fn () => new RunwireExecutionContext($runtime, $completed))->toThrow(LogicException::class);
});
