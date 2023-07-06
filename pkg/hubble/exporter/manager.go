// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-exporter-manager")

type job struct {
	uid, name string
	deadline  time.Time
	opts      []exporteroption.Option
}

type managedExporter struct {
	observeroption.OnDecodedEventFunc
	cancel context.CancelFunc
}

type Manager struct {
	ctx         context.Context
	rateLimiter *rate.Limiter
	lostEvents  int
	waitingJobs []job

	// exporters keeps track of all active Hubble-exporters by UID.
	exporters *sync.Map
	opts      exporteroption.Options
}

var _ watchers.FlowLoggingManager = new(Manager)

func NewManager(ctx context.Context) *Manager {
	return &Manager{
		ctx:       ctx,
		exporters: new(sync.Map),
	}
}

func (m *Manager) Configure(opts ...exporteroption.Option) error {
	conf := exporteroption.Default
	for _, opt := range opts {
		err := opt(&conf)
		if err != nil {
			return err
		}
	}
	m.opts = conf

	if m.opts.Limit > 0 {
		m.rateLimiter = rate.NewLimiter(time.Second, int64(m.opts.Limit))
	}

	for _, job := range m.waitingJobs {
		err := m.Start(job.uid, job.name, job.deadline, job.opts)
		if err != nil {
			log.WithField("name", job.name).WithError(err).Warn("failed to start waiting job")
		}
	}
	return nil
}

func (m *Manager) Start(uid, name string, deadline time.Time, opts []exporteroption.Option) error {
	if m.opts.Path == "" {
		m.waitingJobs = append(m.waitingJobs, job{uid: uid, name: name, deadline: deadline, opts: opts})
		return fmt.Errorf("tried starting Hubble-exporter on unconfigured manager. It will start later")
	}

	if deadline.Before(time.Now()) {
		return fmt.Errorf("deadline is in the past")
	}
	conf := []exporteroption.Option{
		exporteroption.WithPath(filepath.Join(m.opts.Path, uid, name+".json")),
		exporteroption.WithMaxBackups(m.opts.MaxBackups),
		exporteroption.WithMaxSizeMB(m.opts.MaxSizeMB),
	}
	if m.opts.Compress {
		conf = append(conf, exporteroption.WithCompress())
	}

	logger := log.WithFields(logrus.Fields{
		"uid":  uid,
		"name": name,
	})

	ctx, cancel := context.WithDeadline(m.ctx, deadline)
	exp, err := NewExporter(ctx, logger, conf...)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create exporter: %w", err)
	}
	me := managedExporter{
		OnDecodedEventFunc: exp.OnDecodedEvent,
		cancel:             cancel,
	}
	_, exists := m.exporters.LoadOrStore(uid, me)
	if exists {
		// It is ok to lose managed exporter here as it set up structures
		// without opening any files yet. We only need to clean up the context.
		cancel()
		return fmt.Errorf("Hubble-exporter for %q (named: %q) is already active", uid, name)
	}
	return nil
}

func (m *Manager) Stop(uid string) error {
	me, loaded := m.exporters.LoadAndDelete(uid)
	if !loaded {
		return fmt.Errorf("Tried deleting Hubble-exporter with %q that doesn't exist", uid)
	}
	me.(managedExporter).cancel()
	return nil
}

func (m *Manager) onDecodedEvent(ctx context.Context, ev *v1.Event) (bool, error) {
	var multiErr error
	m.exporters.Range(func(_, me any) bool {
		_, err := me.(managedExporter).OnDecodedEventFunc(ctx, ev)
		multiErr = errors.Join(multiErr, err)
		return true
	})
	return false, multiErr
}

// rateLimit returns stop=true when processing should stop due to reachin rate limit.
func (m *Manager) rateLimit(ctx context.Context) (stop bool, err error) {
	if m.rateLimiter == nil {
		return false, nil
	}
	// Count lost events when we are over the limit.
	if !m.rateLimiter.Allow() {
		m.lostEvents++
		return true, nil
	}
	// Log when there were events lost.
	if m.lostEvents > 0 {
		event := &v1.Event{
			Event: &flowpb.LostEvent{
				Source:        flowpb.LostEventSource_HUBBLE_EXPORTER_MANAGER_LIMIT,
				NumEventsLost: uint64(m.lostEvents),
			},
		}
		m.lostEvents = 0
		return m.onDecodedEvent(ctx, event)
	}
	return false, nil
}

func (m *Manager) OnDecodedEvent(ctx context.Context, ev *v1.Event) (bool, error) {
	var multiErr error

	stop, err := m.rateLimit(ctx)
	multiErr = errors.Join(multiErr, err)
	if stop {
		return false, multiErr
	}

	_, err = m.onDecodedEvent(ctx, ev)
	multiErr = errors.Join(multiErr, err)
	return false, multiErr
}
