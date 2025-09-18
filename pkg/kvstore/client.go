// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/spanstat"
)

// Client is the client to interact with the kvstore (i.e., etcd).
type Client interface {
	// IsEnabled returns true if kvstore support is enabled,
	// and the client can be used.
	IsEnabled() bool

	BackendOperations
}

type clientImpl struct {
	enabled bool

	cfg    Config
	opts   ExtraOptions
	logger *slog.Logger

	stats *spanstat.SpanStat

	BackendOperations
}

func (cl *clientImpl) IsEnabled() bool {
	return cl.enabled
}

func (cl *clientImpl) Start(hctx cell.HookContext) (err error) {
	cl.stats.Start()
	defer func() { cl.stats.EndError(err) }()

	cl.logger.Info("Establishing connection to kvstore")
	client, errCh := NewClient(context.Background(), cl.logger, cl.cfg.KVStore, cl.cfg.KVStoreOpt, cl.opts)

	select {
	case err = <-errCh:
	case <-hctx.Done():
		err = hctx.Err()
	}

	if err != nil {
		if client != nil {
			client.Close()
		}

		return fmt.Errorf("failed to establish connection to kvstore: %w", err)
	}

	cl.logger.Info("Connection to kvstore successfully established")
	cl.BackendOperations = client

	return nil
}

func (cl *clientImpl) Stop(cell.HookContext) error {
	if cl.BackendOperations != nil {
		cl.BackendOperations.Close()
	}
	return nil
}

// commands returns the script commands suitable to be used in production environments.
func (cl *clientImpl) commands() map[string]script.Cmd {
	if !cl.IsEnabled() {
		return nil
	}

	cmds := cmds{client: cl}
	return map[string]script.Cmd{
		"kvstore/list": cmds.list(),
	}
}

// NewClient returns a new kvstore client based on the configuration
func NewClient(ctx context.Context, logger *slog.Logger, selectedBackend string, opts map[string]string, options ExtraOptions) (BackendOperations, chan error) {
	// Channel used to report immediate errors, module.newClient will
	// create and return a different channel, caller doesn't need to know
	errChan := make(chan error, 1)
	defer close(errChan)

	module := getBackend(selectedBackend)
	if module == nil {
		errChan <- fmt.Errorf("unknown key-value store type %q. See cilium.link/err-kvstore for details", selectedBackend)
		return nil, errChan
	}

	if err := module.setConfig(logger, opts); err != nil {
		errChan <- err
		return nil, errChan
	}

	return module.newClient(ctx, logger, options)
}
