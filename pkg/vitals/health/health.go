// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/sirupsen/logrus"

	"golang.org/x/exp/maps"
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
	// health CLI to unmarshal health status into health.StatusNode.
	JSON() ([]byte, error)

	Timestamp() time.Time
}

type statusNodeReporter interface {
	upsertStatus(Identifier, StatusV2)
	removeStatusTree(Identifier)
}

// Health provides exported functions for accessing health status data.
// As well, provides unexported functions for use during module apply.
type Health interface {
	// All returns a copy of all module statuses.
	// This includes unknown status for modules that have not reported a status yet.
	All() []Status

	// Get returns a copy of a modules status, by module ID.
	// This includes unknown status for modules that have not reported a status yet.
	Get(Identifier) (Status, error)

	// Stats returns a map of the number of module statuses reported by level.
	Stats() map[Level]uint64

	// Stop stops the health provider from processing updates.
	Stop(context.Context) error

	// Subscribe to health status updates.
	Subscribe(context.Context, func(Update), func(error))

	// forModule creates a moduleID scoped reporter handle.
	forModule(cell.FullModuleID) (statusNodeReporter, error)

	// processed returns the number of updates processed.
	processed() uint64
}

type StatusResult struct {
	Update
	FullModuleID Identifier
	Stopped      bool
}

// Status is a modules last health state, including the last update.
type Status struct {
	// Update is the last reported update for a module.
	Update

	FullModuleID Identifier

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

type StatusV2 struct {
	ID      Identifier
	Level   Level
	Message string
	Feature Feature
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

type healthProviderParams struct {
	cell.In
	DB *statedb.DB
}

type Feature string

// NewHealthProvider starts and returns a health status which processes
// health status updates.
func NewHealthProvider(pp healthProviderParams) (Health, error) {
	p := &healthProvider{
		moduleStatuses: make(map[string]Status),
		byLevel:        make(map[Level]uint64),
		running:        true,
		db:             pp.DB,
	}

	// Example for how we might start to index by different types of data.
	featureIndex := statedb.Index[StatusV2, Feature]{
		Name: "id",
		FromObject: func(s StatusV2) index.KeySet {
			return index.NewKeySet([]byte(s.Feature))
		},
		FromKey: func(k Feature) index.Key {
			return index.Key([]byte(k))
		},
		Unique: false,
	}

	idIndex := statedb.Index[StatusV2, Identifier]{
		Name: "id",
		FromObject: func(s StatusV2) index.KeySet {
			return index.NewKeySet([]byte(s.ID.String()))
		},
		FromKey: func(k Identifier) index.Key {
			return index.Key([]byte(k.String()))
		},
		Unique: true,
	}
	var err error
	p.statusTable, err = statedb.NewTable("health-status", idIndex)
	p.pathIndex = idIndex
	p.featureIndex = featureIndex
	if err != nil {
		return nil, err
	}

	if err := p.db.RegisterTable(p.statusTable); err != nil {
		return nil, err
	}
	p.obs, p.emit, p.complete = stream.Multicast[Update]()

	return p, nil
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

func (p *healthProvider) removePrefix(prefix Identifier) error {
	tx := p.db.WriteTxn(p.statusTable)
	q := p.pathIndex.Query(prefix)
	iter := p.statusTable.Prefix(tx, q)
	for {
		o, _, ok := iter.Next()
		if !ok {
			break
		}
		fmt.Println("[tom-debug7] iter prefix:", o)
		_, _, err := p.statusTable.Delete(tx, o)
		if err != nil {
			return fmt.Errorf("failed to delete status %s: %w", prefix.String(), err)
		}
	}
	tx.Commit()
	return nil
}

// func (p *healthProvider) getPrefix() {
// 	tx := p.db.ReadTxn()
// 	q := p.pathIndex.Query(Identifier{"agent", "infra", "vitals", "cilium-endpoint-8"})
// 	iter := p.statusTable.Prefix(tx, q)
// 	for {
// 		o, _, ok := iter.Next()
// 		if !ok {
// 			break
// 		}
// 		fmt.Println("[tom-debug7] iter prefix:", o)
// 	}
// }

func (p *healthProvider) upsertStatus(id Identifier, s StatusV2) {
	tx := p.db.WriteTxn(p.statusTable)
	if _, _, err := p.statusTable.Insert(tx, s); err != nil {
		panic(err)
	}
	tx.Commit()
}

var log = logrus.New().WithField("subsys", "health-vitals")

// Finish stops the status provider, and waits for all updates to be processed or
// returns an error if the context is cancelled first.
func (p *healthProvider) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = false // following this, no new reporters will send.
	p.complete(nil)   // complete the observable, no new subscribers will receive further updates.
	return nil
}

// forModule returns a module scoped status reporter handle for emitting status updates.
// This is used to automatically provide declared modules with a status reported.
func (p *healthProvider) forModule(moduleID cell.FullModuleID) (statusNodeReporter, error) {
	tx := p.db.WriteTxn(p.statusTable)
	_, _, err := p.statusTable.Insert(tx, StatusV2{
		ID:      NewIdentifier(moduleID),
		Level:   StatusUnknown,
		Message: "no status reported yet",
	})
	if err != nil {
		tx.Abort()
		return nil, err
	}
	tx.Commit()

	return &reporter{
		ident:  NewIdentifier(moduleID),
		upsert: p.upsertStatus,
		delete: func(path Identifier) {
			if err := p.removePrefix(path); err != nil {
				log.WithError(err).Error("failed to remove status tree")
			}
		},
	}, nil
}

// All returns a copy of all the latest statuses.
func (p *healthProvider) All() []Status {
	// tx := p.db.ReadTxn()
	// iter, := p.statusTable.All(tx)
	// ss := make([]Status, 0, iter.Count())
	// for {
	// 	o, _, ok := iter.Next()
	// 	if !ok {
	// 		break
	// 	}
	// 	ss = append(ss, Status{
	// 		FullModuleID: s.ID,
	// 	})
	// }
	// sort.Slice(all, func(i, j int) bool {
	// 	return all[i].FullModuleID.String() < all[j].FullModuleID.String()
	// })
	return []Status{}
}

// Get returns the latest status for a module, by module ID.
func (p *healthProvider) Get(moduleID Identifier) (Status, error) {
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
	db             *statedb.DB
	statusTable    statedb.RWTable[StatusV2]
	pathIndex      statedb.Index[StatusV2, Identifier]
	featureIndex   statedb.Index[StatusV2, Feature]

	obs      stream.Observable[Update]
	emit     func(Update)
	complete func(error)
}

// reporter is a handle for emitting status updates.
type reporter struct {
	ident  Identifier
	upsert func(Identifier, StatusV2)
	delete func(Identifier)
}

func (r *reporter) upsertStatus(id Identifier, s StatusV2) {
	r.upsert(id, s)
}

func (r *reporter) removeStatusTree(path Identifier) {
	r.delete(path)
}
