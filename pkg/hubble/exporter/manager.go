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

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-exporter-manager")

type managedExporter struct {
	observeroption.OnDecodedEventFunc
	cancel context.CancelFunc
}

type Manager struct {
	ctx context.Context

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
	return nil
}

func (m *Manager) Start(uid, name string, deadline time.Time, opts []exporteroption.Option) error {
	if m.opts.Path == "" {
		return fmt.Errorf("tried starting Hubble-exporter on unconfigured manager")
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
		return nil
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

func (m *Manager) OnDecodedEvent(ctx context.Context, ev *v1.Event) (bool, error) {
	var multiErr error
	m.exporters.Range(func(_, me any) bool {
		_, err := me.(managedExporter).OnDecodedEventFunc(ctx, ev)
		multiErr = errors.Join(multiErr, err)
		return true
	})
	return false, multiErr
}
