// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/promise"
)

func TestCell(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	// create directory structure and config inputs
	dir, hubble, relay := directories(t)

	// init hive
	ctx := t.Context()
	var serverConfig *WatchedServerConfig

	hive := hive.New(
		cell.Provide(newWatchedConfig),
		cell.Config(Config{
			TLS:              true,
			TLSCertFile:      hubble.certFile,
			TLSKeyFile:       hubble.privkeyFile,
			TLSClientCAFiles: hubble.caFiles,
		}),
		cell.Invoke(func(p promise.Promise[*WatchedServerConfig]) {
			if p != nil {
				go func() {
					serverConfig, _ = p.Await(ctx)
				}()
			}
		}),
	)

	// start hive
	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	// create tmp certs after a delay
	go func() {
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
		setup(t, hubble, relay)
		t.Cleanup(func() {
			cleanup(dir)
		})
	}()

	require.Eventually(t, func() bool {
		return serverConfig != nil
	}, 5*time.Second, 100*time.Millisecond, "TLS server config promise should resolve after a delay")

	if err := hive.Stop(tlog, ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestCellDisabled(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t)
	})

	ctx := t.Context()
	var cfgPromise promise.Promise[*WatchedServerConfig]

	hive := hive.New(
		cell.Provide(newWatchedConfig),
		cell.Config(Config{
			TLS: false,
		}),
		cell.Invoke(func(p promise.Promise[*WatchedServerConfig]) {
			cfgPromise = p
		}),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if cfgPromise != nil {
		t.Fatalf("certloader unexpectedly enabled")
	}

	if err := hive.Stop(tlog, ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("failed to stop: %s", err)
	}
}
