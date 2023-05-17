package cell

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/stream"
	"github.com/cilium/workerpool"
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

type update struct {
	Level
	ModuleID string
	Message  string
}

type StatusReporter interface {
	OK(status string)
	Stopped(reason string)
	Degraded(reason string)
}

// =======================================

type probedReporter struct {
	sync.RWMutex
	moduleID   string
	name       string
	lastStatus *Status
}

func (p *probedReporter) OK(status string) {
	p.Lock()
	defer p.Unlock()
	t := time.Now()
	p.lastStatus.Level = StatusOK
	p.lastStatus.Message = status
	p.lastStatus.LastOK = t
	p.lastStatus.LastUpdated = t
}

func (p *probedReporter) Stopped(reason string) {
	p.Lock()
	defer p.Unlock()
	p.lastStatus.Level = StatusStopped
	p.lastStatus.Message = reason
	p.lastStatus.LastUpdated = time.Now()
}

func (p *probedReporter) Degraded(reason string) {
	p.Lock()
	defer p.Unlock()
	p.lastStatus.Level = StatusDegraded
	p.lastStatus.Message = reason
	p.lastStatus.LastUpdated = time.Now()
}

func (p *probedReporter) Run(ProbeContext) Status {
	p.RLock()
	defer p.RUnlock()
	if p.lastStatus == nil {
		p.lastStatus = &Status{
			update: update{
				Level:    StatusUnknown,
				ModuleID: p.moduleID,
				Message:  "No status reported yet",
			},
		}
	}
	return *p.lastStatus
}

func (p *probedReporter) ID() string {
	return fmt.Sprintf("%s/%s", p.moduleID, p.name)
}

// Prober impl:

type ProbeContext context.Context

type ProbeInterface interface {
	ID() string
	Run(ProbeContext) Status
}

type statusProber struct {
	sync.Mutex
	probes       []ProbeInterface
	statuses     map[string]Status
	runCollector sync.Once
	statusCh     chan Status
	wp           *workerpool.WorkerPool
}

func newStatusProber() *statusProber {
	return &statusProber{
		statuses: make(map[string]Status),
		statusCh: make(chan Status, 128),
	}
}

func (s *statusProber) startCollecting(ctx context.Context) {
	go func() {
		<-ctx.Done()
		close(s.statusCh)
	}()
	go func() {
		for status := range s.statusCh {
			s.statuses[status.ModuleID] = status
		}
	}()
}

func (s *statusProber) evalProbes(ctx context.Context) error {
	for _, probe := range s.probes {
		s.wp.Submit(probe.ID(), func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			// Add [0, 1s) of jitter to avoid all probes running at once.
			<-time.After(time.Millisecond * time.Duration(rand.Int63n(1000)))
			s.statusCh <- probe.Run(ctx)
			return nil
		})
	}
	_, err := s.wp.Drain()
	return err
}

func (s *statusProber) Run(ctx context.Context) {
	s.Lock()
	defer s.Unlock()
	s.startCollecting(ctx)
	for {
		// Each iteration has a total timeout of 5 seconds.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := s.evalProbes(ctx); err != nil {
			log.WithError(err).Error("Failed to evaluate probes")
		}
		cancel()
	}
}

// =======================================

type Status struct {
	update
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

func NewStatusProvider() *StatusProvider {
	p := &StatusProvider{
		updates:        make(chan update),
		moduleStatuses: make(map[string]Status),
	}
	p.Observable, p.emit, p.complete = stream.Multicast[Status]()
	return p
}

type StatusProvider struct {
	mu      sync.Mutex
	updates chan update
	// moduleStatuses is the *latest* status, bucketed by module ID.
	moduleStatuses map[string]Status

	stream.Observable[Status]
	emit     func(Status)
	complete func(error)
}

type reporter struct {
	*StatusProvider
	moduleID string
}

func (r *reporter) Degraded(reason string) {
	r.process(update{ModuleID: r.moduleID, Level: StatusDegraded, Message: reason})
}

func (r *reporter) Stopped(reason string) {
	r.process(update{ModuleID: r.moduleID, Level: StatusStopped, Message: reason})
}

func (r *reporter) OK(status string) {
	r.process(update{ModuleID: r.moduleID, Level: StatusOK, Message: status})
}

func (p *StatusProvider) forModule(moduleID string) StatusReporter {
	p.mu.Lock()
	p.moduleStatuses[moduleID] = Status{update: update{ModuleID: moduleID}}
	p.mu.Unlock()
	return &reporter{moduleID: moduleID, StatusProvider: p}
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

func (p *StatusProvider) process(u update) {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := p.moduleStatuses[u.ModuleID]

	t := time.Now()
	s.LastUpdated = t
	if u.Level == StatusOK {
		s.LastOK = t
	}
	s.update = u
	p.moduleStatuses[u.ModuleID] = s
	p.emit(s)
}

func (p *StatusProvider) Stop() {
	p.complete(nil)
}
