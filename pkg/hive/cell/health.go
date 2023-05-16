package cell

import (
	"fmt"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/stream"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type Level string

const (
	LevelDown      Level = "Down"
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
	Down(reason string) // TODO: Disabled() instead? Don't report when stopping?
	Degraded(reason string)
}

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

func (r *reporter) Down(reason string) {
	r.process(update{ModuleID: r.moduleID, Level: LevelDown, Message: reason})
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
	s.LastUpdated = time.Now()
	if u.Level == StatusOK {
		s.LastOK = time.Now()
	}
	s.update = u
	p.moduleStatuses[u.ModuleID] = s
	p.emit(s)
}

func (p *StatusProvider) Stop() {
	p.complete(nil)
}
