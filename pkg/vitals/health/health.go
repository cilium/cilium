// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/sirupsen/logrus"
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
	AllV2() []StatusV2

	All() []Status

	// Get returns a copy of a modules status, by module ID.
	// This includes unknown status for modules that have not reported a status yet.
	Get(Identifier) (Status, error)

	// Stats returns a map of the number of module statuses reported by level.
	Stats() map[Level]uint64

	// Subscribe to health status updates.
	Subscribe(context.Context, func(Update), func(error))

	Start(context.Context)

	Stop(context.Context)

	// forModule creates a moduleID scoped reporter handle.
	forModule(cell.FullModuleID) (statusNodeReporter, error)
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
	ID      Identifier // stable!
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
		db:             pp.DB,

		stop:    make(chan struct{}),
		updates: make(chan update),
	}

	// Example for how we might start to index by different types of data.
	featureIndex := statedb.Index[StatusV2, Feature]{
		Name: "feature",
		FromObject: func(s StatusV2) index.KeySet {
			return index.NewKeySet([]byte(s.Feature))
		},
		FromKey: func(k Feature) index.Key {
			return index.Key([]byte(k))
		},
		Unique: false,
	}

	// Index by level, so we can efficiently query for all modules of a given level.
	levelIndex := statedb.Index[StatusV2, Level]{
		Name: "level",
		FromObject: func(s StatusV2) index.KeySet {
			return index.NewKeySet([]byte(s.Level))
		},
		FromKey: func(k Level) index.Key {
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
	p.statusTable, err = statedb.NewTable("health-status", idIndex,
		featureIndex, levelIndex)
	p.pathIndex = idIndex
	p.featureIndex = featureIndex
	p.levelIndex = levelIndex
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

func (p *healthProvider) removePrefix(prefix Identifier) error {
	tx := p.db.WriteTxn(p.statusTable)
	q := p.pathIndex.Query(prefix)
	iter := p.statusTable.Prefix(tx, q)
	for {
		o, _, ok := iter.Next()
		if !ok {
			break
		}
		_, _, err := p.statusTable.Delete(tx, o)
		if err != nil {
			return fmt.Errorf("failed to delete status %s: %w", prefix.String(), err)
		}
	}
	tx.Commit()
	return nil
}

func (p *healthProvider) Start(ctx context.Context) {
	go p.runLoop(ctx)
}

const updateMaxBatchSize = 16

func (p *healthProvider) runLoop(ctx context.Context) {
	batch := make([]update, 0, updateMaxBatchSize)
	p.running.Store(true)
	for {
		select {
		case <-p.stop:
			log.Info("stopping health provider")
			return
		case <-ctx.Done():
			// TODO: cleanup
			log.Info("context cancelled, stopping health provider")
			return
		case u := <-p.updates:
			switch u.updateType {
			case "upsert", "delete":
				batch = append(batch, u)
			default:
				log.WithFields(
					logrus.Fields{
						"updateType": u.updateType,
						"id":         u.id,
						"status":     u.s,
					}).Error("BUG: unknown update type")
			}
			if len(batch) >= updateMaxBatchSize {
				p.handleBatch(batch)
				batch = batch[:0]
			}
		case <-inctimer.After(time.Second):
			if len(batch) == 0 {
				continue
			}

			p.handleBatch(batch)

			batch = batch[:0]
		}
	}
}

func (p *healthProvider) handleBatch(batch []update) {
	tx := p.db.WriteTxn(p.statusTable)
	defer tx.Commit()
	for _, u := range batch {
		switch u.updateType {
		case "upsert":
			if _, _, err := p.statusTable.Insert(tx, u.s); err != nil {
				log.WithField("status", u.s).WithError(err).Error("BUG: failed to insert status")
				tx.Abort()
				return
			}
		case "delete":
			q := p.pathIndex.Query(u.id)
			iter := p.statusTable.Prefix(tx, q)
			for {
				o, _, ok := iter.Next()
				if !ok {
					break
				}
				_, _, err := p.statusTable.Delete(tx, o)
				if err != nil {
					log.WithField("status", u.s).WithError(err).Error("BUG: failed to delete status")
					tx.Abort()
					return
				}
			}
		}
	}
}

type update struct {
	updateType string
	id         Identifier
	s          StatusV2
}

var log = logrus.New().WithField("subsys", "health-vitals")

// Finish stops the status provider, and waits for all updates to be processed or
// returns an error if the context is cancelled first.
func (p *healthProvider) Stop(ctx context.Context) {
	close(p.stop)
}

// forModule returns a module scoped status reporter handle for emitting status updates.
// This is used to automatically provide declared modules with a status reported.
func (p *healthProvider) forModule(moduleID cell.FullModuleID) (statusNodeReporter, error) {
	return &reporter{
		ident: NewIdentifier(moduleID),
		upsert: func(path Identifier, s StatusV2) {
			if !p.running.Load() {
				log.Warn("health provider not running yet, dropping update")
			}
			p.updates <- update{
				updateType: "upsert",
				id:         path,
				s:          s,
			}
		},
		delete: func(path Identifier) {
			if !p.running.Load() {
				log.Warn("health provider not running yet, dropping update")
			}
			p.updates <- update{
				updateType: "delete",
				id:         path,
			}
		},
	}, nil
}

func (p *healthProvider) All() []Status {
	return []Status{}
}

func (p *healthProvider) AllV2() []StatusV2 {
	tx := p.db.ReadTxn()
	iter, _ := p.statusTable.All(tx)
	all := make([]StatusV2, 0)
	for {
		o, _, ok := iter.Next()
		if !ok {
			break
		}
		all = append(all, o)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].ID.String() < all[j].ID.String()
	})
	return all
}

// Get returns the latest status for a module, by module ID.
func (p *healthProvider) Get(moduleID Identifier) (Status, error) {
	return Status{}, nil
}

func (p *healthProvider) Stats() map[Level]uint64 {
	freqs := map[Level]uint64{}
	tx := p.db.ReadTxn()
	for _, l := range []Level{StatusOK, StatusDegraded, StatusStopped} {
		q := p.levelIndex.Query(l)
		iter, _ := p.statusTable.Get(tx, q)
		var count uint64
		for {
			_, _, ok := iter.Next()
			if !ok {
				break
			}
			count++
		}
		freqs[l] = count
	}
	return freqs
}

type healthProvider struct {
	numProcessed atomic.Uint64

	byLevel        map[Level]uint64
	moduleStatuses map[string]Status
	db             *statedb.DB
	statusTable    statedb.RWTable[StatusV2]
	pathIndex      statedb.Index[StatusV2, Identifier]
	featureIndex   statedb.Index[StatusV2, Feature]
	levelIndex     statedb.Index[StatusV2, Level]
	updates        chan update
	stop           chan struct{}
	running        atomic.Bool

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
