// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// defaultClient is the default client initialized by initClient
	defaultClient BackendOperations
	// defaultClientSet is a channel that is closed whenever the defaultClient
	// is set.
	defaultClientSet = make(chan struct{})
)

func initClient(ctx context.Context, logger *slog.Logger, module backendModule, opts *ExtraOptions) error {
	scopedLog := logger.With(fieldKVStoreModule, module.getName())
	c, errChan := module.newClient(ctx, scopedLog, opts)
	if c == nil {
		err := <-errChan
		logging.Fatal(scopedLog, "Unable to create kvstore client", logfields.Error, err)
	}

	defaultClient = c
	select {
	case <-defaultClientSet:
		// avoid closing channel already closed.
	default:
		close(defaultClientSet)
	}

	go func() {
		err, isErr := <-errChan
		if isErr && err != nil {
			logging.Fatal(scopedLog, "Unable to connect to kvstore", logfields.Error, err)
		}
	}()

	return nil
}

// Client returns the global kvstore, blocking until it has been configured
func Client() BackendOperations {
	<-defaultClientSet
	return defaultClient
}

// NewClient returns a new kvstore client based on the configuration
func NewClient(ctx context.Context, logger *slog.Logger, selectedBackend string, opts map[string]string, options *ExtraOptions) (BackendOperations, chan error) {
	// Channel used to report immediate errors, module.newClient will
	// create and return a different channel, caller doesn't need to know
	errChan := make(chan error, 1)
	defer close(errChan)

	// If in-memory backend is registered (i.e. we're testing), use it regardless of the
	// requested backend.
	if _, found := registeredBackends[InMemoryModuleName]; found {
		selectedBackend = InMemoryModuleName
	}

	module := getBackend(selectedBackend)
	if module == nil {
		errChan <- fmt.Errorf("unknown key-value store type %q. See cilium.link/err-kvstore for details", selectedBackend)
		return nil, errChan
	}

	if err := module.setConfig(logger, opts); err != nil {
		errChan <- err
		return nil, errChan
	}

	if err := module.setExtraConfig(options); err != nil {
		errChan <- err
		return nil, errChan
	}

	return module.newClient(ctx, logger, options)
}
