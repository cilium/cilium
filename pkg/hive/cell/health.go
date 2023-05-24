package cell

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/stream"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// How big the queue buffer for health status updates should be.
// Insufficient will result in reporter status updates blocking while
// waiting for the queue to be processed.
const updatesBufferSize = 2048

// Level denotes what kind an update is.
type Level string

const (
	StatusUnknown  Level = "Unknown"
	StatusStopped  Level = "Stopped"
	StatusDegraded Level = "Degraded"
	StatusOK       Level = "OK"
)

// StatusReporter provides a method of declaring a Modules health status.
type StatusReporter interface {
	// OK declares that a Module has achieved a desired state and has not entered
	// any unexpected or incorrect states.
	// Modules should only declare themselves as 'OK' once they have stabilized,
	// rather than during their initial state. This should be left to be reported
	// as the default "unknown" to denote that the module has not reached a "ready"
	// health state.
	OK(status string)

	// Stopped reports that a module has completed, and will no longer report any
	// health status.
	Stopped(reason string)

	// Degraded declares that a module has entered a degraded state.
	// This means that it may have failed to provide it's intended services, or
	// to perform it's desired task.
	Degraded(reason string, err error)
}

// Health provides exported functions for accessing health status data.
// As well, provides unexported functions for use during module apply.
type Health interface {
	// All returns a copy of all module statuses.
	// This includes unknown status for modules that have not reported a status yet.
	All() []Status

	// Get returns a copy of a modules status, by module ID.
	// This includes unknown status for modules that have not reported a status yet.
	Get(string) *Status

	// forModule creates a moduleID scoped reporter handle.
	forModule(string) StatusReporter
}

// Update is an event that denotes the change of a modules health state.
type Update struct {
	Level
	ModuleID string
	Message  string
	Err      error
}

// Status is a modules last health state, including the last update.
type Status struct {
	Update
	Stopped     bool
	LastOK      time.Time
	LastUpdated time.Time
}

func (s *Status) String() string {
	var sinceLast string
	if s.LastUpdated.IsZero() {
		sinceLast = "never"
	} else {
		sinceLast = time.Since(s.LastUpdated).String() + " ago"
	}
	return fmt.Sprintf("Status{ModuleID: %s, Level: %s, Since: %s, Message: %s, Err: %v}",
		s.ModuleID, s.Level, sinceLast, s.Message, s.Err)
}

// NewHealthProvider starts and returns a health status which collects emitted
// health status declarations and updates module health state.
func NewHealthProvider() *HealthProvider {
	p := &HealthProvider{
		updates:        make(chan Update, updatesBufferSize),
		done:           make(chan struct{}),
		moduleStatuses: make(map[string]Status),
	}

	p.obs, p.emit, p.complete = stream.Multicast[Update]()

	return p
}

func (p *HealthProvider) Start(ctx context.Context) error {
	if p.started.Load() {
		return fmt.Errorf("health status recorder is already started")
	}
	defer p.started.Store(true)
	// Listen for updates, use buffered channel to avoid blocking.
	go func() {
		for u := range p.updates {
			prev := func() Status {
				p.mu.Lock()
				defer p.mu.Unlock()
				t := time.Now()
				prev := p.moduleStatuses[u.ModuleID]
				ns := Status{
					Update:      u,
					LastUpdated: t,
				}
				switch u.Level {
				case StatusOK:
					ns.LastOK = t
				case StatusStopped:
					// If Stopped, set that module was stopped and preserve last known status.
					ns = prev
					ns.Stopped = true
				}
				p.moduleStatuses[u.ModuleID] = ns
				log.WithField("status", ns.String()).Debug("Processed new health status")
				return prev
			}()
			p.processed.Add(1)
			if prev.Stopped {
				log.Warnf("module %q reported health status after being Stopped", u.ModuleID)
			}
		}
		close(p.done)
	}()
	return nil
}

// Finish stops the status provider, and waits for all updates to be processed or
// returns an error if the context is cancelled first.
func (p *HealthProvider) Stop(ctx context.Context) error {
	if !p.started.Load() {
		return fmt.Errorf("health status recorder is not running")
	}
	defer p.started.Store(false)
done:
	for {
		select {
		case <-inctimer.After(time.Millisecond * 100):
			processed := p.processed.Load()
			queued := p.queued.Load()
			if processed >= queued {
				break done
			}
		case <-ctx.Done():
			return fmt.Errorf("failed to drain health status provider: %w", ctx.Err())
		}
	}
	close(p.updates)
	return nil
}

// forModule returns a module scoped status reporter handle for emitting status updates.
// This is used to automatically provide declared modules with a status reported.
func (p *HealthProvider) forModule(moduleID string) StatusReporter {
	p.mu.Lock()
	p.moduleStatuses[moduleID] = Status{Update: Update{
		ModuleID: moduleID,
		Level:    StatusUnknown,
		Message:  "No status reported yet"},
	}
	p.mu.Unlock()

	return &reporter{
		moduleID: moduleID,
		emit: func(u Update) {
			p.queued.Add(1)
			p.updates <- u
		},
	}
}

// All returns a copy of all the latest statuses.
func (p *HealthProvider) All() []Status {
	p.mu.RLock()
	all := maps.Values(p.moduleStatuses)
	p.mu.RUnlock()
	slices.SortFunc(all, func(a, b Status) bool {
		return a.ModuleID < b.ModuleID
	})
	return all
}

// Get returns the latest status for a module, by module ID.
func (p *HealthProvider) Get(moduleID string) *Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s, ok := p.moduleStatuses[moduleID]
	if ok {
		return &s
	}
	return nil
}

type HealthProvider struct {
	mu      lock.RWMutex
	updates chan Update
	done    chan struct{}

	started   atomic.Bool
	processed atomic.Uint64
	queued    atomic.Uint64

	moduleStatuses map[string]Status

	obs      stream.Observable[Update]
	emit     func(Update)
	complete func(error)
}

// reporter is a handle for emitting status updates.
type reporter struct {
	moduleID string
	emit     func(Update)
}

func (r *reporter) Degraded(reason string, err error) {
	r.emit(Update{ModuleID: r.moduleID, Level: StatusDegraded, Message: reason, Err: err})
}

func (r *reporter) Stopped(reason string) {
	r.emit(Update{ModuleID: r.moduleID, Level: StatusStopped, Message: reason})
}

func (r *reporter) OK(status string) {
	r.emit(Update{ModuleID: r.moduleID, Level: StatusOK, Message: status})
}
