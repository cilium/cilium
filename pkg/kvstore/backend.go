// Copyright 2017-2019 Authors of Cilium
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
	"time"

	"google.golang.org/grpc"
)

type backendOption struct {
	// description is the description of the option
	description string

	// value is the value the option has been configured to
	value string

	// validate, if set, is called to validate the value before assignment
	validate func(value string) error
}

type backendOptions map[string]*backendOption

// ExtraOptions represents any options that can not be represented in a textual
// format and need to be set programmatically.
type ExtraOptions struct {
	DialOption []grpc.DialOption

	// ClusterSizeDependantInterval defines the function to calculate
	// intervals based on cluster size
	ClusterSizeDependantInterval func(baseInterval time.Duration) time.Duration
}

// StatusCheckInterval returns the interval of status checks depending on the
// cluster size and the current connectivity state
//
// nodes      OK  Failing
// 1         20s       3s
// 4         45s       7s
// 8       1m05s      11s
// 32      1m45s      18s
// 128     2m25s      24s
// 512     3m07s      32s
// 2048    3m46s      38s
// 8192    4m30s      45s
func (e *ExtraOptions) StatusCheckInterval(allConnected bool) time.Duration {
	interval := 30 * time.Second

	// Reduce the interval while connectivity issues are being detected
	if !allConnected {
		interval = 5 * time.Second
	}

	if e != nil && e.ClusterSizeDependantInterval != nil {
		interval = e.ClusterSizeDependantInterval(interval)
	}
	return interval
}

// backendModule is the interface that each kvstore backend has to implement.
type backendModule interface {
	// getName must return the name of the backend
	getName() string

	// setConfig must configure the backend with the specified options.
	// This function is called once before newClient().
	setConfig(opts map[string]string) error

	// setExtraConfig sets more options in the kvstore that are not able to
	// be set by strings.
	setExtraConfig(opts *ExtraOptions) error

	// setConfigDummy must configure the backend with dummy configuration
	// for testing purposes. This is a replacement for setConfig().
	setConfigDummy()

	// getConfig must return the backend configuration.
	getConfig() map[string]string

	// newClient must initializes the backend and create a new kvstore
	// client which implements the BackendOperations interface
	newClient(opts *ExtraOptions) (BackendOperations, chan error)

	// createInstance creates a new instance of the module
	createInstance() backendModule
}

var (
	// registeredBackends is a slice of all backends that have registered
	// itself via registerBackend()
	registeredBackends = map[string]backendModule{}
)

// registerBackend must be called by kvstore backends to register themselves
func registerBackend(name string, module backendModule) {
	if _, ok := registeredBackends[name]; ok {
		log.Panicf("backend with name '%s' already registered", name)
	}

	registeredBackends[name] = module
}

// getBackend finds a registered backend by name
func getBackend(name string) backendModule {
	if backend, ok := registeredBackends[name]; ok {
		return backend.createInstance()
	}

	return nil
}

// BackendOperations are the individual kvstore operations that each backend
// must implement. Direct use of this interface is possible but will bypass the
// tracing layer.
type BackendOperations interface {
	// Connected returns a channel which is closed whenever the kvstore client
	// is connected to the kvstore server. (Only implemented for etcd)
	Connected() <-chan struct{}

	// Disconnected returns a channel which is closed whenever the kvstore
	// client is not connected to the kvstore server. (Only implemented for etcd)
	Disconnected() <-chan struct{}

	// Status returns the status of the kvstore client including an
	// eventual error
	Status() (string, error)

	// LockPath locks the provided path
	LockPath(ctx context.Context, path string) (KVLocker, error)

	// Get returns value of key
	Get(key string) ([]byte, error)

	// GetLocked returns value of key if the client is still holding the given lock.
	GetLocked(key string, lock KVLocker) ([]byte, error)

	// GetPrefix returns the first key which matches the prefix and its value
	GetPrefix(ctx context.Context, prefix string) (string, []byte, error)

	// GetPrefixLocked returns the first key which matches the prefix and its value if the client is still holding the given lock.
	GetPrefixLocked(ctx context.Context, prefix string, lock KVLocker) (string, []byte, error)

	// Set sets value of key
	Set(key string, value []byte) error

	// Delete deletes a key
	Delete(key string) error

	// DeleteLocked deletes a key if the client is still holding the given lock.
	DeleteLocked(key string, lock KVLocker) error

	DeletePrefix(path string) error

	// Update atomically creates a key or fails if it already exists
	Update(ctx context.Context, key string, value []byte, lease bool) error

	// UpdateLocked atomically creates a key or fails if it already exists if the client is still holding the given lock.
	UpdateLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) error

	// UpdateIfDifferent updates a key if the value is different
	UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (bool, error)

	// UpdateIfDifferentLocked updates a key if the value is different and if the client is still holding the given lock.
	UpdateIfDifferentLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (bool, error)

	// CreateOnly atomically creates a key or fails if it already exists
	CreateOnly(ctx context.Context, key string, value []byte, lease bool) (bool, error)

	// CreateOnlyLocked atomically creates a key if the client is still holding the given lock or fails if it already exists
	CreateOnlyLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (bool, error)

	// CreateIfExists creates a key with the value only if key condKey exists
	CreateIfExists(condKey, key string, value []byte, lease bool) error

	// ListPrefix returns a list of keys matching the prefix
	ListPrefix(prefix string) (KeyValuePairs, error)

	// ListPrefixLocked returns a list of keys matching the prefix only if the client is still holding the given lock.
	ListPrefixLocked(prefix string, lock KVLocker) (KeyValuePairs, error)

	// Watch starts watching for changes in a prefix. If list is true, the
	// current keys matching the prefix will be listed and reported as new
	// keys first.
	Watch(w *Watcher)

	// Close closes the kvstore client
	Close()

	// GetCapabilities returns the capabilities of the backend
	GetCapabilities() Capabilities

	// Encodes a binary slice into a character set that the backend
	// supports
	Encode(in []byte) string

	// Decodes a key previously encoded back into the original binary slice
	Decode(in string) ([]byte, error)

	// ListAndWatch creates a new watcher which will watch the specified
	// prefix for changes. Before doing this, it will list the current keys
	// matching the prefix and report them as new keys. Name can be set to
	// anything and is used for logging messages. The Events channel is
	// created with the specified sizes. Upon every change observed, a
	// KeyValueEvent will be sent to the Events channel
	ListAndWatch(name, prefix string, chanSize int) *Watcher
}
