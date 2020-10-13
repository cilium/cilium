// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kvstore

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/option"
)

var (
	// defaultClient is the default client initialized by initClient
	defaultClient BackendOperations
	// defaultClientSet is a channel that is closed whenever the defaultClient
	// is set.
	defaultClientSet = make(chan struct{})
)

func initClient(ctx context.Context, module backendModule, opts *ExtraOptions) error {
	scopedLog := log.WithField(fieldKVStoreModule, module.getName())
	c, errChan := module.newClient(ctx, opts)
	if c == nil {
		err := <-errChan
		scopedLog.WithError(err).Fatal("Unable to create kvstore client")
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
			scopedLog.WithError(err).Fatal("Unable to connect to kvstore")
		}
		if !option.Config.JoinCluster {
			deleteLegacyPrefixes(ctx)
		}
	}()

	return nil
}

// Client returns the global kvstore client or nil if the client is not configured yet
func Client() BackendOperations {
	<-defaultClientSet
	return defaultClient
}

// NewClient returns a new kvstore client based on the configuration
func NewClient(ctx context.Context, selectedBackend string, opts map[string]string, options *ExtraOptions) (BackendOperations, chan error) {
	// Channel used to report immediate errors, module.newClient will
	// create and return a different channel, caller doesn't need to know
	errChan := make(chan error, 1)
	defer close(errChan)

	module := getBackend(selectedBackend)
	if module == nil {
		errChan <- fmt.Errorf("unknown key-value store type %q. See cilium.link/err-kvstore for details", selectedBackend)
		return nil, errChan
	}

	if err := module.setConfig(opts); err != nil {
		errChan <- err
		return nil, errChan
	}

	if err := module.setExtraConfig(options); err != nil {
		errChan <- err
		return nil, errChan
	}

	return module.newClient(ctx, options)
}

// Connected returns a channel which is closed when the following conditions
// are being met at the same time:
// * The kvstore client is configured
// * Connectivity to the kvstore has been established
// * The kvstore has quorum
//
// The channel will *not* be closed if the kvstore client is closed before
// connectivity or quorum has been achieved. It will wait until a new kvstore
// client is configured to again wait for connectivity and quorum.
func Connected() <-chan struct{} {
	c := make(chan struct{})
	go func(c chan struct{}) {
		for {
			if err := <-Client().Connected(context.Background()); err == nil {
				close(c)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}(c)
	return c
}
