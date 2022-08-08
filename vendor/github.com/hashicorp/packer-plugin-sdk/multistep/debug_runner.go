package multistep

import (
	"context"
	"fmt"
	"reflect"
	"sync"
)

// DebugLocation is the location where the pause is occurring when debugging
// a step sequence. "DebugLocationAfterRun" is after the run of the named
// step. "DebugLocationBeforeCleanup" is before the cleanup of the named
// step.
type DebugLocation uint

const (
	DebugLocationAfterRun DebugLocation = iota
	DebugLocationBeforeCleanup
)

// StepWrapper is an interface that wrapped steps can implement to expose their
// inner step names to the debug runner.
type StepWrapper interface {
	// InnerStepName should return the human readable name of the wrapped step.
	InnerStepName() string
}

// DebugPauseFn is the type signature for the function that is called
// whenever the DebugRunner pauses. It allows the caller time to
// inspect the state of the multi-step sequence at a given step.
type DebugPauseFn func(DebugLocation, string, StateBag)

// DebugRunner is a Runner that runs the given set of steps in order,
// but pauses between each step until it is told to continue.
type DebugRunner struct {
	// Steps is the steps to run. These will be run in order.
	Steps []Step

	// PauseFn is the function that is called whenever the debug runner
	// pauses. The debug runner continues when this function returns.
	// The function is given the state so that the state can be inspected.
	PauseFn DebugPauseFn

	l      sync.Mutex
	runner *BasicRunner
}

func (r *DebugRunner) Run(ctx context.Context, state StateBag) {
	r.l.Lock()
	if r.runner != nil {
		panic("already running")
	}
	r.runner = new(BasicRunner)
	r.l.Unlock()

	pauseFn := r.PauseFn

	// If no PauseFn is specified, use the default
	if pauseFn == nil {
		pauseFn = DebugPauseDefault
	}

	// Rebuild the steps so that we insert the pause step after each
	steps := make([]Step, len(r.Steps)*2)
	for i, step := range r.Steps {
		if step == nil {
			continue
		}
		steps[i*2] = step
		name := ""
		if wrapped, ok := step.(StepWrapper); ok {
			name = wrapped.InnerStepName()
		} else {
			name = reflect.Indirect(reflect.ValueOf(step)).Type().Name()
		}
		steps[(i*2)+1] = &debugStepPause{
			name,
			pauseFn,
		}
	}

	// Then just use a basic runner to run it
	r.runner.Steps = steps
	r.runner.Run(ctx, state)
}

// DebugPauseDefault is the default pause function when using the
// DebugRunner if no PauseFn is specified. It outputs some information
// to stderr about the step and waits for keyboard input on stdin before
// continuing.
func DebugPauseDefault(loc DebugLocation, name string, state StateBag) {
	var locationString string
	switch loc {
	case DebugLocationAfterRun:
		locationString = "after run of"
	case DebugLocationBeforeCleanup:
		locationString = "before cleanup of"
	}

	fmt.Printf("Pausing %s step '%s'. Press any key to continue.\n", locationString, name)

	var line string
	fmt.Scanln(&line)
}

type debugStepPause struct {
	StepName string
	PauseFn  DebugPauseFn
}

func (s *debugStepPause) Run(ctx context.Context, state StateBag) StepAction {
	s.PauseFn(DebugLocationAfterRun, s.StepName, state)
	return ActionContinue
}

func (s *debugStepPause) Cleanup(state StateBag) {
	s.PauseFn(DebugLocationBeforeCleanup, s.StepName, state)
}
