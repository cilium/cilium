// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/cilium/stream"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/lock"
)

// Level denotes what kind an update is.
type Level string

const (
	// StatusUnknown is the default status of a Module, prior to it reporting
	// any status.
	// All created
	StatusUnknown Level = "Unknown"

	// StatusStopped is the status of a Module that has completed, further updates
	// will not be processed.
	StatusStopped Level = "Stopped"

	// StatusDegraded is the status of a Module that has entered a degraded state.
	StatusDegraded Level = "Degraded"

	// StatusOK is the status of a Module that has achieved a desired state.
	StatusOK Level = "OK"
)

// HealthReporter provides a method of declaring a Modules health status.
type HealthReporter interface {
	// OK declares that a Module has achieved a desired state and has not entered
	// any unexpected or incorrect states.
	// Modules should only declare themselves as 'OK' once they have stabilized,
	// rather than during their initial state. This should be left to be reported
	// as the default "unknown" to denote that the module has not reached a "ready"
	// health state.
	OK(status string)

	// Stopped reports that a module has completed, and will no longer report any
	// health status.
	// Implementations should differentiate that a stopped module may also be OK or Degraded.
	// Stopping a reporting should only affect future updates.
	Stopped(reason string)

	// Degraded declares that a module has entered a degraded state.
	// This means that it may have failed to provide it's intended services, or
	// to perform it's desired task.
	Degraded(reason string, err error)
}

// Update represents an instantaneous health status update.
type Update interface {
	// Level returns the level of the update.
	Level() Level

	// String returns a string representation of the update.
	String() string

	// JSON returns a JSON representation of the update, this is used by the agent
	// health CLI to unmarshal health status into cell.StatusNode.
	JSON() ([]byte, error)

	Timestamp() time.Time
}

type statusNodeReporter interface {
	setStatus(Update)
}

// Health provides exported functions for accessing health status data.
// As well, provides unexported functions for use during module apply.
type Health interface {
	// All returns a copy of all module statuses.
	// This includes unknown status for modules that have not reported a status yet.
	All() []Status

	// Get returns a copy of a modules status, by module ID.
	// This includes unknown status for modules that have not reported a status yet.
	Get(FullModuleID) (Status, error)

	// Stats returns a map of the number of module statuses reported by level.
	Stats() map[Level]uint64

	// Stop stops the health provider from processing updates.
	Stop(context.Context) error

	// Subscribe to health status updates.
	Subscribe(context.Context, func(Update), func(error))

	// forModule creates a moduleID scoped reporter handle.
	forModule(FullModuleID) statusNodeReporter

	// processed returns the number of updates processed.
	processed() uint64
}

type StatusResult struct {
	Update
	FullModuleID FullModuleID
	Stopped      bool
}

// Status is a modules last health state, including the last update.
type Status struct {
	// Update is the last reported update for a module.
	Update

	FullModuleID FullModuleID

	// Stopped is true when a module has been completed, thus it contains
	// its last reporter status. New updates will not be processed.
	Stopped bool
	// Final is the stopped message, if the module has been stopped.
	Final Update
	// LastOK is the time of the last OK status update.
	LastOK time.Time
	// LastUpdated is the time of the last status update.
	LastUpdated time.Time
}

func (s *Status) JSON() ([]byte, error) {
	if s.Update == nil {
		return nil, nil
	}
	return s.Update.JSON()
}

func (s *Status) Level() Level {
	if s.Update == nil {
		return StatusUnknown
	}
	return s.Update.Level()
}

// String returns a string representation of a Status, implements fmt.Stringer.
func (s *Status) String() string {
	var sinceLast string
	if s.LastUpdated.IsZero() {
		sinceLast = "never"
	} else {
		sinceLast = time.Since(s.LastUpdated).String() + " ago"
	}
	return fmt.Sprintf("Status{ModuleID: %s, Level: %s, Since: %s, Message: %s}",
		s.FullModuleID, s.Level(), sinceLast, s.Update.String())
}

// NewHealthProvider starts and returns a health status which processes
// health status updates.
func NewHealthProvider() Health {
	p := &healthProvider{
		moduleStatuses: make(map[string]Status),
		byLevel:        make(map[Level]uint64),
		running:        true,
	}
	p.obs, p.emit, p.complete = stream.Multicast[Update]()

	return p
}

func (p *healthProvider) Subscribe(ctx context.Context, cb func(Update), complete func(error)) {
	p.obs.Observe(ctx, cb, complete)
}

func (p *healthProvider) processed() uint64 {
	return p.numProcessed.Load()
}

func (p *healthProvider) updateMetricsLocked(prev Update, curr Level) {
	// If an update is processed that transitions the level state of a module
	// then update the level counters.
	if prev.Level() != curr {
		p.byLevel[curr]++
		p.byLevel[prev.Level()]--
	}
}

func (p *healthProvider) process(id FullModuleID, u Update) {
	prev := func() Status {
		p.mu.Lock()
		defer p.mu.Unlock()

		t := time.Now()
		prev := p.moduleStatuses[id.String()]

		// If the module has been stopped, then ignore updates.
		if !p.running {
			return prev
		}

		ns := Status{
			Update:      u,
			LastUpdated: t,
		}

		switch u.Level() {
		case StatusOK:
			ns.LastOK = t
		case StatusStopped:
			// If Stopped, set that module was stopped and preserve last known status.
			ns = prev
			ns.Stopped = true
			ns.Final = u
		}
		p.moduleStatuses[id.String()] = ns
		p.updateMetricsLocked(prev.Update, u.Level())
		log.WithField("status", ns.String()).Debug("Processed new health status")
		return prev
	}()
	p.numProcessed.Add(1)
	p.emit(u)
	if prev.Stopped {
		log.Warnf("module %q reported health status after being Stopped", id)
	}
}

// Finish stops the status provider, and waits for all updates to be processed or
// returns an error if the context is cancelled first.
func (p *healthProvider) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = false // following this, no new reporters will send.
	p.complete(nil)   // complete the observable, no new subscribers will receive further updates.
	return nil
}

var NoStatus = &StatusNode{Message: "No status reported", LastLevel: StatusUnknown}

// forModule returns a module scoped status reporter handle for emitting status updates.
// This is used to automatically provide declared modules with a status reported.
func (p *healthProvider) forModule(moduleID FullModuleID) statusNodeReporter {
	p.mu.Lock()
	p.moduleStatuses[moduleID.String()] = Status{
		FullModuleID: moduleID,
		Update:       NoStatus,
	}
	p.byLevel[StatusUnknown]++
	p.mu.Unlock()

	return &reporter{
		moduleID: moduleID,
		process:  p.process,
	}
}

// All returns a copy of all the latest statuses.
func (p *healthProvider) All() []Status {
	p.mu.RLock()
	all := maps.Values(p.moduleStatuses)
	p.mu.RUnlock()
	sort.Slice(all, func(i, j int) bool {
		return all[i].FullModuleID.String() < all[j].FullModuleID.String()
	})
	return all
}

// Get returns the latest status for a module, by module ID.
func (p *healthProvider) Get(moduleID FullModuleID) (Status, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s, ok := p.moduleStatuses[moduleID.String()]
	if ok {
		return s, nil
	}
	return Status{}, fmt.Errorf("module %q not found", moduleID)
}

func (p *healthProvider) Stats() map[Level]uint64 {
	n := make(map[Level]uint64, len(p.byLevel))
	p.mu.Lock()
	maps.Copy(n, p.byLevel)
	p.mu.Unlock()
	return n
}

type healthProvider struct {
	mu lock.RWMutex

	running      bool
	numProcessed atomic.Uint64

	byLevel        map[Level]uint64
	moduleStatuses map[string]Status

	obs      stream.Observable[Update]
	emit     func(Update)
	complete func(error)
}

// reporter is a handle for emitting status updates.
type reporter struct {
	moduleID FullModuleID
	process  func(FullModuleID, Update)
}

// Degraded reports a degraded status update, should be used when a module encounters a
// a state that is not fully reconciled.
func (r *reporter) setStatus(u Update) {
	r.process(r.moduleID, u)
}
