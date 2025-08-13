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
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestCell(t *testing.T) {
	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)
	})

	// create directory structure and config inputs
	dir, hubble, relay := directories(t)

	// init hive
	ctx := t.Context()
	var err error
	var serverConfig *WatchedServerConfig

	config := testConfig{
		TLS:              true,
		TLSCertFile:      hubble.certFile,
		TLSKeyFile:       hubble.privkeyFile,
		TLSClientCAFiles: hubble.caFiles,
	}

	hive := hive.New(
		cell.ProvidePrivate(func(cfg testConfig) Config {
			return Config(cfg)
		}),
		cell.Provide(NewWatchedServerConfigPromise),
		cell.Config(config),
		cell.Invoke(func(p promise.Promise[*WatchedServerConfig]) {
			if p != nil {
				go func() {
					serverConfig, err = p.Await(ctx)
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
		return err == nil && serverConfig != nil && serverConfig.certFile == config.TLSCertFile
	}, 5*time.Second, 100*time.Millisecond, "TLS server config promise should resolve after a delay")

	if err := hive.Stop(tlog, ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestCellConfigError(t *testing.T) {
	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)
	})

	// init hive
	ctx := t.Context()
	var err error
	var serverConfig *WatchedServerConfig

	hive := hive.New(
		cell.ProvidePrivate(func(cfg testConfig) Config {
			return Config(cfg)
		}),
		cell.Provide(NewWatchedServerConfigPromise),
		//exhaustruct:ignore
		cell.Config(testConfig{
			TLS: true,
		}),
		cell.Invoke(func(p promise.Promise[*WatchedServerConfig]) {
			if p != nil {
				go func() {
					serverConfig, err = p.Await(ctx)
				}()
			}
		}),
	)

	// start hive
	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	// add a small delay
	time.Sleep(time.Second)

	require.Eventually(t, func() bool {
		return err != nil && serverConfig == nil
	}, 5*time.Second, 100*time.Millisecond, "TLS server config promise should resolve with an error after a delay")

	if err := hive.Stop(tlog, ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestCellShutdown(t *testing.T) {
	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)
	})

	// create directory structure and config inputs
	// do not setup certs for this test, we want to test
	// that we can shutdown cleanly before finding certs
	dir, hubble, _ := directories(t)
	t.Cleanup(func() {
		cleanup(dir)
	})

	// init hive
	ctx := t.Context()
	var serverConfig *WatchedServerConfig

	config := testConfig{
		TLS:              true,
		TLSCertFile:      hubble.certFile,
		TLSKeyFile:       hubble.privkeyFile,
		TLSClientCAFiles: hubble.caFiles,
	}

	hive := hive.New(
		cell.ProvidePrivate(func(cfg testConfig) Config {
			return Config(cfg)
		}),
		cell.Provide(NewWatchedServerConfigPromise),
		cell.Config(config),
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

	// add a small delay
	time.Sleep(time.Second)

	// ensure we can stop the hive cleanly, and consequently our cert watcher
	// even when certs have not been resolved yet
	if err := hive.Stop(tlog, ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("failed to stop: %s", err)
	}

	if serverConfig != nil {
		t.Fatalf("serverConfig unexpectedly resolved")
	}
}

func TestCellDisabled(t *testing.T) {
	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t)
	})

	ctx := t.Context()
	var cfgPromise promise.Promise[*WatchedServerConfig]

	hive := hive.New(
		cell.ProvidePrivate(func(cfg testConfig) Config {
			return Config(cfg)
		}),
		cell.Provide(NewWatchedServerConfigPromise),
		//exhaustruct:ignore
		cell.Config(testConfig{
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

type testConfig struct {
	TLS              bool     `mapstructure:"tls"`
	TLSCertFile      string   `mapstructure:"tls-cert-file"`
	TLSKeyFile       string   `mapstructure:"tls-key-file"`
	TLSClientCAFiles []string `mapstructure:"tls-client-ca-files"`
}

func (def testConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("tls", def.TLS, "")
	flags.String("tls-cert-file", def.TLSCertFile, "")
	flags.String("tls-key-file", def.TLSKeyFile, "")
	flags.StringSlice("tls-client-ca-files", def.TLSClientCAFiles, "")
}
