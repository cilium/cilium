package status

import (
	"context"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/stream"
)

type Level string

const (
	LevelDown     Level = "down"
	LevelDegraded Level = "degraded"
	LevelOK       Level = "ok"
)

type update struct {
	ModuleID string
	Level
	Message string

	//Model   map[string]string

	// TODO: How structured should this be? Should we include
	// some JSON encodable payload?
	// Should known faulty states be enumerated?
	// Should we have "knowledge base" for them?
	// Should a module be able to have sub-statuses?
	// Might be nice to be able to include a snapshot of module's metrics
	// here. Or at least the mechanism that exposes the module status could
	// also expose it's metrics. How coupled should status and metrics be?
}

type Reporter interface {
	OK()
	Down(reason string) // TODO: Disabled() instead? Don't report when stopping?
	Degraded(reason string)

	// Also add: RegisterModel(func() Model) ?
	// Report() would be for reactive status reporting
	// towards metrics and alerting, and model (or something)
	// would be for producing detailed status (e.g. daemon/cmd/status.go
	// style).
	// Do we really want the complicated swagger generated models or
	// would it be enough to have "map[jsonKey]jsonValue" type model?
	//
	// Could also assume that it's cheap enough to produce the status
	// model and include it in Update. The module reporting it can decide
	// how often it can create it.
}

type ModuleStatus struct {
	update
	LastOK      time.Time
	LastUpdated time.Time
}

func New() *Provider {
	p := &Provider{
		updates:  make(chan update),
		statuses: make(map[string]ModuleStatus),
	}
	p.src, p.emit, p.complete = stream.Multicast[ModuleStatus]()
	return p
}

type moduleStatusUpdate struct {
	update update
}

type Provider struct {
	mu       sync.Mutex
	updates  chan update
	statuses map[string]ModuleStatus

	src      stream.Observable[ModuleStatus]
	emit     func(ModuleStatus)
	complete func(error)
}

type reporter struct {
	*Provider
	moduleID string
}

func (r *reporter) Degraded(reason string) {
	r.process(update{ModuleID: r.moduleID, Level: LevelDegraded, Message: reason})
}

func (r *reporter) Down(reason string) {
	r.process(update{ModuleID: r.moduleID, Level: LevelDown, Message: reason})
}

func (r *reporter) OK() {
	r.process(update{ModuleID: r.moduleID, Level: LevelOK})
}

func (p *Provider) ForModule(moduleID string) Reporter {
	p.mu.Lock()
	p.statuses[moduleID] = ModuleStatus{update: update{ModuleID: moduleID}}
	p.mu.Unlock()
	return &reporter{moduleID: moduleID, Provider: p}
}

func (p *Provider) All() []ModuleStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Values(p.statuses)
}

// TODO: Idea with Stream() is that we could have subscriber that
// propagates to metrics ("num_degraded") etc. Alternatively we just
// integrate metrics directly into this.
func (p *Provider) Stream(ctx context.Context) <-chan ModuleStatus {
	return stream.ToChannel(ctx, make(chan error, 1), p.src)
}

func (p *Provider) process(u update) {
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

func (p *Provider) Stop() {
	p.complete(nil)
}
