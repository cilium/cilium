// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

func TestExporterStop(t *testing.T) {
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}

	ctx := context.Background()
	exporter, err := newExporter(ctx, log, opts)
	require.NoError(t, err)

	assert.NotNil(t, exporter.cancel)

	err = exporter.Stop()
	assert.NoError(t, err)
	assert.Nil(t, exporter.cancel)
	assert.Nil(t, exporter.writer)

	// Multiple Stop() calls should be safe
	err = exporter.Stop()
	assert.NoError(t, err)
}

func TestExporterGoroutineTermination(t *testing.T) {
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}
	err := WithFieldAggregate([]string{"source.namespace"})(&opts)
	require.NoError(t, err)

	ctx := context.Background()
	exporter, err := newExporter(ctx, log, opts)
	require.NoError(t, err)

	var goroutineStarted, goroutineFinished atomic.Bool

	go func() {
		goroutineStarted.Store(true)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-exporter.ctx.Done():
				goroutineFinished.Store(true)
				return
			case <-ticker.C:
			}
		}
	}()

	require.Eventually(t, func() bool {
		return goroutineStarted.Load()
	}, time.Second, 10*time.Millisecond)

	err = exporter.Stop()
	assert.NoError(t, err)

	require.Eventually(t, func() bool {
		return goroutineFinished.Load()
	}, time.Second, 10*time.Millisecond)
}

func TestDynamicExporterConfigReload(t *testing.T) {
	buf := &bytesWriteCloser{bytes.Buffer{}}
	log := hivetest.Logger(t)

	opts := DefaultOptions
	opts.newWriterFunc = func() (io.WriteCloser, error) {
		return buf, nil
	}

	logger := hivetest.Logger(t)
	dynamicExporter := &dynamicExporter{
		logger:           logger,
		exporterFactory:  &exporterFactory{logger},
		managedExporters: make(map[string]*managedExporter),
	}

	ctx := context.Background()

	buf = &bytesWriteCloser{bytes.Buffer{}}
	exporter1, err := newExporter(ctx, log, opts)
	require.NoError(t, err)

	dynamicExporter.managedExporters["test001"] = &managedExporter{
		config:   &FlowLogConfig{Name: "test001", FilePath: "/tmp/test1.log"},
		exporter: exporter1,
	}

	assert.Len(t, dynamicExporter.managedExporters, 1)
	assert.NotNil(t, exporter1.cancel)

	newConfigs := map[string]ExporterConfig{
		"test001": &FlowLogConfig{Name: "test001", FilePath: "/tmp/test1_updated.log"},
	}

	dynamicExporter.onConfigReload(ctx, newConfigs, 1)

	// onConfigReload should have cancelled the old exporter1's context
	assert.Nil(t, exporter1.cancel)

	// new exporter recreated by onConfigReload for "test001"
	exporter2 := dynamicExporter.managedExporters["test001"].exporter.(*exporter)
	assert.NotEqual(t, exporter1, exporter2)
	assert.NotNil(t, exporter2.cancel)
	assert.Len(t, dynamicExporter.managedExporters, 1)

	//cleanup
	for _, me := range dynamicExporter.managedExporters {
		me.exporter.Stop()
	}
}
