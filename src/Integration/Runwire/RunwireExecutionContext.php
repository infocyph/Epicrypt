<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Integration\Runwire;

use Infocyph\Runwire\Coroutine\CoroutineScope;
use Infocyph\Runwire\Coroutine\TaskLocal;
use Infocyph\Runwire\RequestContext;
use Infocyph\Runwire\Runtime\Enum\RuntimeCapability;
use Infocyph\Runwire\RuntimeContext;
use InvalidArgumentException;
use LogicException;
use WeakMap;

/**
 * Borrows caller-owned Runwire 2.1.1 execution state.
 *
 * No runtime or task is started, owned or completed by Epicrypt.
 */
final class RunwireExecutionContext
{
    private const int MAX_CHECKPOINT_INTERVAL = 1_000_000;

    private static ?TaskLocal $scopeBindingKey = null;

    private readonly ?TaskLocal $scopeProbe;

    private int $checkpoints = 0;

    public function __construct(
        public readonly RuntimeContext $runtime,
        public readonly ?RequestContext $request = null,
        public readonly ?CoroutineScope $scope = null,
        public readonly int $checkpointEvery = 256,
    ) {
        if ($checkpointEvery < 1 || $checkpointEvery > self::MAX_CHECKPOINT_INTERVAL) {
            throw new InvalidArgumentException('Runwire checkpoint interval must be between 1 and 1000000.');
        }

        $this->scopeProbe = $scope === null ? null : self::$scopeBindingKey ??= new TaskLocal();
        if ($scope !== null && $this->scopeProbe !== null) {
            $inherited = $scope->local($this->scopeProbe);
            // Copy the snapshot so new bindings never appear in earlier sibling tasks.
            $bindings = $inherited instanceof WeakMap ? clone $inherited : new WeakMap();
            $bindings[$this] = true;
            $scope->setLocal($this->scopeProbe, $bindings);
        }
        $this->assertActive();
    }

    public function assertActive(): void
    {
        if ($this->runtime->pid !== getmypid()) {
            throw new LogicException('Runwire runtime PID does not match the Epicrypt process.');
        }
        if ($this->request !== null) {
            if ($this->request->runtime() !== $this->runtime || $this->request->completed()) {
                throw new LogicException('Runwire request is completed or belongs to a different runtime.');
            }
            $this->request->cancellation->throwIfCancelled();
        }
        if ($this->scope !== null && $this->scopeProbe !== null) {
            $bindings = $this->scope->local($this->scopeProbe);
            if (!$bindings instanceof WeakMap || !isset($bindings[$this])) {
                throw new LogicException('Runwire scope is not borrowed by the current task.');
            }
            $this->scope->cancellation()->throwIfCancelled();
        }
    }

    /**
     * Reject stale/cancelled borrowed work and yield only with a live scoped scheduler.
     */
    public function checkpoint(): void
    {
        $this->assertActive();
        if (
            $this->scope !== null
            && $this->runtime->supports(RuntimeCapability::RUNWIRE_COROUTINES)
            && ++$this->checkpoints % $this->checkpointEvery === 0
        ) {
            $this->scope->yieldNow();
        }
        $this->assertActive();
    }
}
