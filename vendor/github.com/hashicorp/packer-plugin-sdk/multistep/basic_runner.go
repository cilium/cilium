package multistep

import (
	"context"
	"sync"
	"sync/atomic"
)

type runState int32

const (
	stateIdle runState = iota
	stateRunning
	stateCancelling
)

// BasicRunner is a Runner that just runs the given slice of steps.
type BasicRunner struct {
	// Steps is a slice of steps to run. Once set, this should _not_ be
	// modified.
	Steps []Step

	l     sync.Mutex
	state runState
}

func (b *BasicRunner) Run(ctx context.Context, state StateBag) {

	b.l.Lock()
	if b.state != stateIdle {
		panic("already running")
	}

	doneCh := make(chan struct{})
	b.state = stateRunning
	b.l.Unlock()

	defer func() {
		b.l.Lock()
		b.state = stateIdle
		close(doneCh)
		b.l.Unlock()
	}()

	// This goroutine listens for cancels and puts the StateCancelled key
	// as quickly as possible into the state bag to mark it.
	go func() {
		select {
		case <-ctx.Done():
			state.Put(StateCancelled, true)
		case <-doneCh:
		}
	}()

	for _, step := range b.Steps {
		if step == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			state.Put(StateCancelled, true)
			break
		}
		// We also check for cancellation here since we can't be sure
		// the goroutine that is running to set it actually ran.
		if runState(atomic.LoadInt32((*int32)(&b.state))) == stateCancelling {
			state.Put(StateCancelled, true)
			break
		}

		action := step.Run(ctx, state)
		defer step.Cleanup(state)

		if _, ok := state.GetOk(StateCancelled); ok {
			break
		}

		if action == ActionHalt {
			state.Put(StateHalted, true)
			break
		}
	}
}
