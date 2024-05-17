// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type providerParams struct {
	cell.In

	DB          *statedb.DB
	Lifecycle   cell.Lifecycle
	StatusTable statedb.RWTable[types.Status]
	Logger      *slog.Logger
}

type provider struct {
	db *statedb.DB

	stopped     atomic.Bool
	statusTable statedb.RWTable[types.Status]
	logger      *slog.Logger
}

const TableName = "health"

func newHealthV2Provider(params providerParams) types.Provider {
	p := &provider{
		statusTable: params.StatusTable,
		db:          params.DB,
		logger:      params.Logger,
	}
	params.Lifecycle.Append(p)
	return p
}

func (p *provider) Start(ctx cell.HookContext) error {
	return nil
}

func (p *provider) Stop(ctx cell.HookContext) error {
	p.stopped.Store(true)
	tx := p.db.ReadTxn()
	iter, _ := p.statusTable.All(tx)
	for {
		s, rev, ok := iter.Next()
		if !ok {
			break
		}
		p.logger.Info(fmt.Sprintf("%s (rev=%d)", s.ID.String(), rev))
	}
	return nil
}

func (p *provider) ForModule(mid cell.FullModuleID) cell.Health {
	return &moduleReporter{
		logger: p.logger,
		id:     types.Identifier{Module: mid},
		upsert: func(s types.Status) error {
			if p.stopped.Load() {
				return fmt.Errorf("provider is stopped, no more updates will take place")
			}
			tx := p.db.WriteTxn(p.statusTable)
			defer tx.Abort()
			old, _, found := p.statusTable.Get(tx, PrimaryIndex.QueryFromObject(s))
			if found && !old.Stopped.IsZero() {
				return fmt.Errorf("reporting for %q has been stopped", s.ID)
			}
			s.Count = 1
			// If a similar status already exists, increment count, otherwise start back
			// at zero.
			if found && old.Level == s.Level && old.Message == s.Message && old.Error == s.Error {
				s.Count = old.Count + 1
			}
			if _, _, err := p.statusTable.Insert(tx, s); err != nil {
				return fmt.Errorf("upsert status %s: %w", s, err)
			}

			// To avoid excess debug logs, only report upserts if it's a new status,
			// is not-OK or is a state change (ex. Degraded -> OK).
			if !found || s.Level != types.LevelOK || old.Level != s.Level {
				lastLevel := "none"
				if old.Level != "" {
					lastLevel = string(old.Level)
				}
				p.logger.Debug("upserting health status",
					slog.String("lastLevel", lastLevel),
					slog.String("reporter-id", s.ID.String()),
					slog.String("status", s.String()))
			}

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
			iter, _ := p.statusTable.Prefix(tx, q)
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

			p.logger.Debug("delete health sub-tree",
				slog.String("prefix", i.String()),
				slog.Int("deleted", deleted))
			tx.Commit()
			return nil
		},
		stop: func(i types.Identifier) error {
			if p.stopped.Load() {
				return fmt.Errorf("provider is stopped, no more updates will take place")
			}
			tx := p.db.WriteTxn(p.statusTable)
			defer tx.Abort()
			old, _, found := p.statusTable.Get(tx, PrimaryIndex.Query(i.HealthID()))
			if !found {
				// Nothing to do.
				return nil
			}
			if !old.Stopped.IsZero() {
				return fmt.Errorf("reporting for %q has been stopped", i)
			}
			old.Stopped = time.Now()
			if _, _, err := p.statusTable.Insert(tx, old); err != nil {
				return fmt.Errorf("stopping reporter - upsert status %s: %w", old, err)
			}
			tx.Commit()
			p.logger.Debug("stopping health reporter", slog.String("reporter-id", i.String()))
			return nil
		},
		providerStopped: p.stopped.Load,
	}
}

type moduleReporter struct {
	logger          *slog.Logger
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
		logger:       r.logger,
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
		r.logger.Warn("report on stopped reporter", slog.String("id", r.id.String()))
	}
	ts := time.Now()
	if err := r.upsert(types.Status{
		ID:      r.id,
		Level:   types.LevelOK,
		Message: msg,
		LastOK:  ts,
		Updated: ts,
	}); err != nil {
		r.logger.Error("failed to upsert ok health status", slog.String(logfields.Error, err.Error()))
	}
}

func (r *moduleReporter) Degraded(msg string, err error) {
	if r.stopped.Load() {
		r.logger.Warn("report on stopped reporter", slog.String("id", r.id.String()))
	}
	if err := r.upsert(types.Status{
		ID:      r.id,
		Level:   types.LevelDegraded,
		Message: msg,
		Error:   err.Error(),
		Updated: time.Now(),
	}); err != nil {
		r.logger.Error("failed to upsert degraded health status", slog.String(logfields.Error, err.Error()))
	}
}

// Stopped declares a reporter scope stopped, and will block further updates to it while
// maintaining the last known status of the reporter.
func (r *moduleReporter) Stopped(msg string) {
	r.stopped.Store(true)
	if err := r.stop(r.id); err != nil {
		r.logger.Error("failed to delete reporter status tree", slog.String(logfields.Error, err.Error()))
	}
}

// Close completely closes out a tree, it will remove all health statuses below
// this reporter scope.
func (r *moduleReporter) Close() {
	if err := r.deletePrefix(r.id); err != nil {
		r.logger.Error("failed to delete reporter status tree", slog.String(logfields.Error, err.Error()))
	}
}
