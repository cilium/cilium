package readiness

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
)

var Cell = cell.Module(
	"readiness",
	"Coordinates readiness of modules controlling datapath",

	cell.Provide(New),
)

type Readiness struct {
	mu     lock.Mutex
	waited bool
	chans  map[string]chan struct{}
}

func New() *Readiness {
	return &Readiness{}
}

// Add registers a module to be waited for readiness. Returns callback
// to mark as ready. If a module fails initialization it should shut down
// via hive.Shutdowner.
func (r *Readiness) Add(moduleId string) func() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.waited {
		panic("Readiness.Add() called after Readiness.Wait()")
	}

	ch := make(chan struct{})
	r.chans[moduleId] = ch
	return func() { close(ch) }
}

// Wait until all registered modules have signalled readiness.
func (r *Readiness) Wait(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waited = true
	for name, ch := range r.chans {
		select {
		case <-ctx.Done():
			return fmt.Errorf("Context canceled while waiting for %s", name)
		case <-ch:
		}
	}
	return nil
}
