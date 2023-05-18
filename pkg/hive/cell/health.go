package cell

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/stream"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type Level string

const (
	StatusUnknown  Level = "Unknown"
	StatusStopped  Level = "Stopped"
	StatusDegraded Level = "Degraded"
	StatusOK       Level = "OK"
)

type Update struct {
	Level
	ModuleID string
	Message  string
}

type StatusReporter interface {
	OK(status string)
	Stopped(reason string)
	Degraded(reason string)
}

type Status struct {
	Update
	LastOK      time.Time
	LastUpdated time.Time
}

func (s *Status) String() string {
	var sinceLast string
	if s.LastUpdated.IsZero() {
		sinceLast = "never"
	} else {
		sinceLast = fmt.Sprintf("%d ago", time.Since(s.LastUpdated))
	}
	return fmt.Sprintf("%-30s %-9s: %s (%s)",
		s.ModuleID, s.Level, s.Message, sinceLast)
}

// How big the queue buffer for health status updates should be.
// Insufficient will result in reporter status updates blocking while
// waiting for the queue to be processed.
const updatesBufferSize = 2048

func NewHealthStatus() *HealthStatus {
	p := &HealthStatus{
		updates:        make(chan Update, updatesBufferSize),
		done:           make(chan struct{}),
		moduleStatuses: make(map[string]Status),
	}

	// Use multicast to fan out updates to potential multiple observers.
	//
	// TODO: How do we prevent external subs from blocking?
	// 		Do we need the external subs or can we just keep it all unexported.
	p.obs, p.emit, p.complete = stream.Multicast[Update]()

	// Listen for updates, use buffered channel to avoid blocking.
	go func() {
		for s := range p.updates {
			p.mu.Lock()
			t := time.Now()
			ns := Status{
				Update:      s,
				LastUpdated: t,
			}
			if s.Level == StatusOK {
				ns.LastOK = t
			}
			p.moduleStatuses[s.ModuleID] = ns
			p.processed.CompareAndSwap(p.processed.Load(), p.processed.Load()+1)
			p.mu.Unlock()
		}
		close(p.done)
	}()

	// Start observing the stream of updates, all updates will be sent to the
	// to the updates channel.
	//
	// Updates are observed in order, and processed in order by the goroutine.
	p.obs.Observe(context.Background(),
		func(s Update) {
			p.updates <- s
		},
		func(err error) {
			if err != nil {
				log.WithError(err).Error("StatusProvider stream failed")
			} else {
				log.WithError(err).Error("StatusProvider stream failed")
			}
			close(p.updates)
		})
	return p
}

// forModule returns a module scoped status reporter handle for emitting status updates.
func (p *HealthStatus) forModule(moduleID string) StatusReporter {
	p.mu.Lock()
	p.moduleStatuses[moduleID] = Status{Update: Update{
		ModuleID: moduleID,
		Level:    StatusUnknown,
		Message:  "No status reported yet"},
	}
	p.mu.Unlock()

	return &reporter{
		moduleID: moduleID,
		emit:     p.emit,
	}
}

// All returns a copy of all the latest statuses.
func (p *HealthStatus) All() []Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	all := maps.Values(p.moduleStatuses)
	slices.SortFunc(all, func(a, b Status) bool {
		return a.ModuleID < b.ModuleID
	})
	return all
}

// Get returns the latest status for a module, by module ID.
func (p *HealthStatus) Get(moduleID string) *Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.moduleStatuses[moduleID]
	if ok {
		return &s
	}
	return nil
}

// Finish stops the status provider, and waits for all updates to be processed or
// returns an error if the context is cancelled first.
func (p *HealthStatus) Finish(ctx context.Context) error {
	p.complete(nil)
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("failed to drain health status provider: %w", ctx.Err())
	}
}

type HealthStatus struct {
	mu        sync.Mutex
	updates   chan Update
	processed atomic.Uint64
	done      chan struct{}
	// moduleStatuses is the *latest* status, bucketed by module ID.
	moduleStatuses map[string]Status

	obs      stream.Observable[Update]
	emit     func(Update)
	complete func(error)
}

func (p *HealthStatus) Processed() uint64 {
	return p.processed.Load()
}

// reporter is a handle for emitting status updates.
type reporter struct {
	emit     func(Update)
	moduleID string
}

func (r *reporter) Degraded(reason string) {
	r.emit(Update{ModuleID: r.moduleID, Level: StatusDegraded, Message: reason})
}

func (r *reporter) Stopped(reason string) {
	r.emit(Update{ModuleID: r.moduleID, Level: StatusStopped, Message: reason})
}

func (r *reporter) OK(status string) {
	r.emit(Update{ModuleID: r.moduleID, Level: StatusOK, Message: status})
}
