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

func NewStatusProvider() *StatusProvider {
	p := &StatusProvider{
		updates:        make(chan Update, updatesBufferSize),
		done:           make(chan struct{}),
		moduleStatuses: make(map[string]Status),
	}
	// ???
	//ch := make(chan Update, updatesBufferSize)
	//obs := stream.FromChannel(ch)

	// Use multicast to fan out updates to potential multiple observers.
	// TODO: How do we prevent external subs from blocking?
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
	//
	// TODO: What value does this bring?
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

// forModule provides a status reporter handle for emitting status updates.
func (p *StatusProvider) forModule(moduleID string) StatusReporter {
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

func (p *StatusProvider) All() []Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	all := maps.Values(p.moduleStatuses)
	slices.SortFunc(all, func(a, b Status) bool {
		return a.ModuleID < b.ModuleID
	})
	return all
}

func (p *StatusProvider) Get(moduleID string) *Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.moduleStatuses[moduleID]
	if ok {
		return &s
	}
	return nil
}

func (p *StatusProvider) Stop() {
	p.complete(nil)
}

func (p *StatusProvider) finish(ctx context.Context) error {
	p.complete(nil)
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("failed to drain health status provider: %w", ctx.Err())
	}
}

type StatusProvider struct {
	mu        sync.Mutex
	updates   chan Update
	processed atomic.Uint64
	done      chan struct{}
	// moduleStatuses is the *latest* status, bucketed by module ID.
	// todo: use pointer swaps to avoid copying the map.
	moduleStatuses map[string]Status

	obs      stream.Observable[Update]
	emit     func(Update)
	complete func(error)
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
