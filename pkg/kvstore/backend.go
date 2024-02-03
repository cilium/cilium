// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"

	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/time"
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

type ClusterSizeDependantIntervalFunc func(baseInterval time.Duration) time.Duration

// ExtraOptions represents any options that can not be represented in a textual
// format and need to be set programmatically.
type ExtraOptions struct {
	DialOption []grpc.DialOption

	// ClusterSizeDependantInterval defines the function to calculate
	// intervals based on cluster size
	ClusterSizeDependantInterval ClusterSizeDependantIntervalFunc

	// NoLockQuorumCheck disables the lock acquisition quorum check
	NoLockQuorumCheck bool

	// ClusterName is the name of each etcd cluster
	ClusterName string

	// BootstrapComplete is an optional channel that can be provided to signal
	// to the client that bootstrap is complete. If provided, the client will
	// have an initial rate limit equal to etcd.bootstrapQps and be updated to
	// etcd.qps after this channel is closed.
	BootstrapComplete <-chan struct{}
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
	newClient(ctx context.Context, opts *ExtraOptions) (BackendOperations, chan error)

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
	// is connected to the kvstore server.
	Connected(ctx context.Context) <-chan error

	// Disconnected returns a channel which is closed whenever the kvstore
	// client is not connected to the kvstore server. (Only implemented for etcd)
	Disconnected() <-chan struct{}

	// Status returns the status of the kvstore client including an
	// eventual error
	Status() (string, error)

	// StatusCheckErrors returns a channel which receives status check
	// errors
	StatusCheckErrors() <-chan error

	// LockPath locks the provided path
	LockPath(ctx context.Context, path string) (KVLocker, error)

	// Get returns value of key
	Get(ctx context.Context, key string) ([]byte, error)

	// GetIfLocked returns value of key if the client is still holding the given lock.
	GetIfLocked(ctx context.Context, key string, lock KVLocker) ([]byte, error)

	// Delete deletes a key. It does not return an error if the key does not exist.
	Delete(ctx context.Context, key string) error

	// DeleteIfLocked deletes a key if the client is still holding the given lock. It does not return an error if the key does not exist.
	DeleteIfLocked(ctx context.Context, key string, lock KVLocker) error

	DeletePrefix(ctx context.Context, path string) error

	// Update creates or updates a key.
	Update(ctx context.Context, key string, value []byte, lease bool) error

	// UpdateIfLocked updates a key if the client is still holding the given lock.
	UpdateIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) error

	// UpdateIfDifferent updates a key if the value is different
	UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (bool, error)

	// UpdateIfDifferentIfLocked updates a key if the value is different and if the client is still holding the given lock.
	UpdateIfDifferentIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (bool, error)

	// CreateOnly atomically creates a key or fails if it already exists
	CreateOnly(ctx context.Context, key string, value []byte, lease bool) (bool, error)

	// CreateOnlyIfLocked atomically creates a key if the client is still holding the given lock or fails if it already exists
	CreateOnlyIfLocked(ctx context.Context, key string, value []byte, lease bool, lock KVLocker) (bool, error)

	// ListPrefix returns a list of keys matching the prefix
	ListPrefix(ctx context.Context, prefix string) (KeyValuePairs, error)

	// ListPrefixIfLocked returns a list of keys matching the prefix only if the client is still holding the given lock.
	ListPrefixIfLocked(ctx context.Context, prefix string, lock KVLocker) (KeyValuePairs, error)

	// Close closes the kvstore client
	Close(ctx context.Context)

	// Encodes a binary slice into a character set that the backend
	// supports
	Encode(in []byte) string

	// Decodes a key previously encoded back into the original binary slice
	Decode(in string) ([]byte, error)

	// ListAndWatch creates a new watcher which will watch the specified
	// prefix for changes. Before doing this, it will list the current keys
	// matching the prefix and report them as new keys. The Events channel is
	// created with the specified sizes. Upon every change observed, a
	// KeyValueEvent will be sent to the Events channel
	ListAndWatch(ctx context.Context, prefix string, chanSize int) *Watcher

	// RegisterLeaseExpiredObserver registers a function which is executed when
	// the lease associated with a key having the given prefix is detected as expired.
	// If the function is nil, the previous observer (if any) is unregistered.
	RegisterLeaseExpiredObserver(prefix string, fn func(key string))

	BackendOperationsUserMgmt
}

// BackendOperationsUserMgmt are the kvstore operations for users management.
type BackendOperationsUserMgmt interface {
	// UserEnforcePresence creates a user in the kvstore if not already present, and grants the specified roles.
	UserEnforcePresence(ctx context.Context, name string, roles []string) error

	// UserEnforcePresence deletes a user from the kvstore, if present.
	UserEnforceAbsence(ctx context.Context, name string) error
}
