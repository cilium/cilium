// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthv2

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/healthv2/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
)

var logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "healthv2")

type HealthProviderParams struct {
	cell.In

	DB          *statedb.DB
	Lifecycle   cell.Lifecycle
	StatusTable statedb.RWTable[types.Status]
}

type HealthProvider struct {
	db *statedb.DB

	stopped     atomic.Bool
	statusTable statedb.RWTable[types.Status]
}

const HealthTableName = "health"

func newHealthV2Provider(params HealthProviderParams) types.Provider {
	p := &HealthProvider{
		statusTable: params.StatusTable,
		db:          params.DB,
	}
	params.Lifecycle.Append(p)
	return p
}

func (p *HealthProvider) Start(ctx cell.HookContext) error {
	return nil
}

func (p *HealthProvider) Stop(ctx cell.HookContext) error {
	p.stopped.Store(true)
	tx := p.db.ReadTxn()
	iter, _ := p.statusTable.All(tx)
	for {
		s, rev, ok := iter.Next()
		if !ok {
			break
		}
		logger.Infof("%s (rev=%d)", s.ID.String(), rev)
	}
	return nil
}

func (p *HealthProvider) ForModule(mid cell.FullModuleID) cell.Health {
	return &moduleReporter{
		id: types.Identifier{Module: mid},
		upsert: func(s types.Status) error {
			if p.stopped.Load() {
				return fmt.Errorf("provider is stopped, no more updates will take place")
			}
			tx := p.db.WriteTxn(p.statusTable)
			defer tx.Abort()
			old, _, found := p.statusTable.First(tx, PrimaryIndex.QueryFromObject(s))
			if found && !old.Stopped.IsZero() {
				return fmt.Errorf("reporting for %q has been stopped", s.ID)
			}
			s.Count = 1
			// If a similar status already exists, increment count, otherwise start back
			// at zero.
			if found && old.Level == s.Level && old.Message == s.Message {
				s.Count = old.Count + 1
			}
			if _, _, err := p.statusTable.Insert(tx, s); err != nil {
				return fmt.Errorf("upsert status %s: %w", s, err)
			}

			logger.WithField("reporter-id", s.ID.String()).
				WithField("status", s).
				Debugf("upserting health status")
			tx.Commit()
			return nil
		},
		deletePrefix: func(i types.Identifier) error {
			if p.stopped.Load() {
				return fmt.Errorf("provider is stopped, no more updates will take place")
			}
			tx := p.db.WriteTxn(p.statusTable)
			defer tx.Abort()
			q := PrimaryIndex.Query(types.HealthID(i.String()))
			iter, _ := p.statusTable.LowerBound(tx, q)
			var deleted int
			for {
				o, _, ok := iter.Next()
				if !ok {
					break
				}
				if _, _, err := p.statusTable.Delete(tx, types.Status{
					ID: o.ID,
				}); err != nil {
					return fmt.Errorf("deleting prunable child %s: %w", i, err)
				}
				deleted++
			}

			logger.WithField("prefix", i).
				WithField("deleted", deleted).
				Debugf("delete health sub-tree")
			tx.Commit()
			return nil
		},
		stop: func(i types.Identifier) error {
			if p.stopped.Load() {
				return fmt.Errorf("provider is stopped, no more updates will take place")
			}
			tx := p.db.WriteTxn(p.statusTable)
			defer tx.Abort()
			old, _, found := p.statusTable.First(tx, PrimaryIndex.QueryFromObject(types.Status{ID: i}))
			if found && !old.Stopped.IsZero() {
				return fmt.Errorf("reporting for %q has been stopped", i)
			}
			old.Stopped = time.Now()
			if _, _, err := p.statusTable.Insert(tx, old); err != nil {
				return fmt.Errorf("stopping reporter - upsert status %s: %w", old, err)
			}
			tx.Commit()
			logger.WithField("reporter-id", i.String()).
				Debugf("stopping health reporter")
			return nil
		},
		providerStopped: p.stopped.Load,
	}
}

type moduleReporter struct {
	id              types.Identifier
	stopped         atomic.Bool
	providerStopped func() bool
	upsert          func(types.Status) error
	stop            func(types.Identifier) error
	deletePrefix    func(types.Identifier) error
}

func (r *moduleReporter) newScope(name string) *moduleReporter {
	return &moduleReporter{
		id:           r.id.WithSubComponent(name),
		upsert:       r.upsert,
		deletePrefix: r.deletePrefix,
		stop:         r.stop,
	}
}

func (r *moduleReporter) NewScope(name string) cell.Health {
	return r.newScope(name)
}

func (r *moduleReporter) NewScopeWithContext(ctx context.Context, name string) cell.Health {
	s := r.newScope(name)
	go func() {
		<-ctx.Done()
		s.stopped.Store(true)
		s.Close()
	}()
	return s
}

func (r *moduleReporter) OK(msg string) {
	if r.stopped.Load() {
		logger.WithField("id", r.id).Warn("report on stopped reporter")
	}
	ts := time.Now()
	if err := r.upsert(types.Status{
		ID:      r.id,
		Level:   types.LevelOK,
		Message: msg,
		LastOK:  ts,
		Updated: ts,
	}); err != nil {
		logger.WithError(err).Errorf("failed to upsert ok health status")
	}
}

func (r *moduleReporter) Degraded(msg string, err error) {
	if r.stopped.Load() {
		logger.WithField("id", r.id).Warn("report on stopped reporter")
	}
	if err := r.upsert(types.Status{
		ID:      r.id,
		Level:   types.LevelDegraded,
		Error:   err,
		Updated: time.Now(),
	}); err != nil {
		logger.WithError(err).Errorf("failed to upsert degraded health status")
	}
}

// Stopped declares a reporter scope stopped, and will block further updates to it while
// maintaining the last known status of the reporter.
func (r *moduleReporter) Stopped(msg string) {
	r.stopped.Store(true)
	if err := r.stop(r.id); err != nil {
		logger.WithError(err).Error("failed to delete reporter status tree")
	}
}

// Close completely closes out a tree, it will remove all health statuses below
// this reporter scope.
func (r *moduleReporter) Close() {
	if err := r.deletePrefix(r.id); err != nil {
		logger.WithError(err).Error("failed to delete reporter status tree")
	}
}
