// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/stream"
)

const (
	LevelDown     Level = "Down"
	LevelDegraded Level = "Degraded"
	LevelOK       Level = "OK"
)

type (
	// Level tracks health level.
	Level string

	update struct {
		ModuleID string
		Level
		Message string
	}

	// HealthReporter tracks module health.
	HealthReporter interface {
		OK(status string)
		Down(reason string) // TODO: Disabled() instead? Don't report when stopping?
		Degraded(reason string)
	}

	// ModuleHealth tracks module health state,
	ModuleHealth struct {
		update
		LastOK      time.Time
		LastUpdated time.Time
	}
)

// String returns a human representation.
func (s *ModuleHealth) String() string {
	return fmt.Sprintf("%-30s %-9s: %s (%.2fs ago)",
		s.ModuleID, s.Level, s.Message, time.Since(s.LastUpdated).Seconds())
}

// HealthProvider tracks modules health state.
type HealthProvider struct {
	mu       sync.Mutex
	updates  chan update
	statuses map[string]ModuleHealth

	src      stream.Observable[ModuleHealth]
	emit     func(ModuleHealth)
	complete func(error)
}

// NewHealthProvider returns a new instance.
func NewHealthProvider() *HealthProvider {
	p := &HealthProvider{
		updates:  make(chan update),
		statuses: make(map[string]ModuleHealth),
	}
	p.src, p.emit, p.complete = stream.Multicast[ModuleHealth]()
	return p
}

func (p *HealthProvider) ForModule(moduleID string) HealthReporter {
	p.mu.Lock()
	p.statuses[moduleID] = ModuleHealth{update: update{ModuleID: moduleID}}
	p.mu.Unlock()
	return &reporter{moduleID: moduleID, HealthProvider: p}
}

func (p *HealthProvider) All() []ModuleHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	all := maps.Values(p.statuses)
	slices.SortFunc(all, func(a, b ModuleHealth) bool {
		return a.ModuleID < b.ModuleID
	})
	return all
}

func (p *HealthProvider) Get(moduleID string) *ModuleHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.statuses[moduleID]
	if ok {
		return &s
	}
	return nil
}

// TODO: Idea with Stream() is that we could have subscriber that
// propagates to metrics ("num_degraded") etc. Alternatively we just
// integrate metrics directly into this.
// TODO: Should we emit []ModuleHealth?
func (p *HealthProvider) Stream(ctx context.Context) <-chan ModuleHealth {
	return nil
	// BOZO!!
	// return stream.ToChannel(ctx, make(chan error, 1), p.src)
}

func (p *HealthProvider) process(u update) {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := p.statuses[u.ModuleID]
	s.LastUpdated = time.Now()
	if u.Level == LevelOK {
		s.LastOK = time.Now()
	}
	s.update = u
	p.statuses[u.ModuleID] = s
	p.emit(s)
}

func (p *HealthProvider) Stop() {
	p.complete(nil)
}

type reporter struct {
	*HealthProvider

	moduleID string
}

// TODO: These methods should be rate limited. Might also make sense to flip this around and
// do what pkg/status does with probing as constructing the status string isn't free.
// E.g. instead of HealthReporter being available, we'd depend on "StatusRegistry" that's
// module-id scoped and we'd be able to register multiple probes.

func (r *reporter) Degraded(reason string) {
	r.process(update{ModuleID: r.moduleID, Level: LevelDegraded, Message: reason})
}

func (r *reporter) Down(reason string) {
	r.process(update{ModuleID: r.moduleID, Level: LevelDown, Message: reason})
}

func (r *reporter) OK(status string) {
	r.process(update{ModuleID: r.moduleID, Level: LevelOK, Message: status})
}
