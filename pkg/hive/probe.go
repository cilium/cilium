package hive

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/workerpool"
)

type ProbeContext context.Context

type ProbeInterface interface {
	Run(ProbeContext) error
}

type Prober interface {
	Append(ProbeInterface)
}

type DefaultProbeManager struct {
	mu        lock.Mutex
	modProbes map[string]moduleProbeRegister
	// TODO: Observable?
}

func (p *DefaultProbeManager) Run(ctx context.Context) error {
	wp := workerpool.New(10)

	for {
		for mid, pr := range p.modProbes {
			pr := pr
			wp.Submit(mid, func(ctx context.Context) error {
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				return pr.run(ctx)
			})
		}
	}
}

type moduleProbeRegister struct {
	ps            []ProbeInterface
	lastProbeTime time.Time
	lastStatus    string
	lastError     error
}

func (pr *moduleProbeRegister) run(ctx context.Context) error {
	for _, probe := range pr.ps {
		if err := probe.Run(ctx); err != nil {
			pr.lastStatus = "Degraded" // TODO
			pr.lastError = err
		} else {
			pr.lastStatus = "OK" // TODO
			pr.lastError = nil
		}
	}
	pr.lastProbeTime = time.Now()
	return nil
}

func NewDefaultProbeManager() *DefaultProbeManager {
	return &DefaultProbeManager{
		modProbes: make(map[string]moduleProbeRegister),
	}
}

type moduleProber struct {
	*DefaultProbeManager
	moduleID string
}

func (p *DefaultProbeManager) forModule(moduleID string) Prober {
	p.mu.Lock()
	defer p.mu.Unlock()
	mp := &moduleProber{
		moduleID: moduleID,
	}
	return mp
}

func (p *moduleProber) Append(probe ProbeInterface) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr := p.modProbes[p.moduleID]
	pr.ps = append(pr.ps, probe)
	p.modProbes[p.moduleID] = pr
}
