// Copyright 2017-2018 Authors of Cilium
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
	"encoding/json"
	"time"

	"github.com/cilium/cilium/common/types"
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

// backendBase is the base type to be embedded by all backends
type backendBase struct {
	opts backendOptions
}

// backendModule is the interface that each kvstore backend has to implement.
type backendModule interface {
	// getName must return the name of the backend
	getName() string

	// setConfig must configure the backend with the specified options.
	// This function is called once before newClient().
	setConfig(opts map[string]string) error

	// setConfigDummy must configure the backend with dummy configuration
	// for testing purposes. This is a replacement for setConfig().
	setConfigDummy()

	// getConfig must return the backend configuration.
	getConfig() map[string]string

	// newClient must initializes the backend and create a new kvstore
	// client which implements the BackendOperations interface
	newClient() (BackendOperations, error)
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
		return backend
	}

	return nil
}

// BackendOperations are the individual kvstore operations that each backend
// must implement. Direct use of this interface is possible but will bypass the
// tracing layer.
type BackendOperations interface {
	// BEGIN Obsolete API
	GetValue(k string) (json.RawMessage, error)
	SetValue(k string, v interface{}) error
	InitializeFreeID(path string, firstID uint32) error
	GetMaxID(key string, firstID uint32) (uint32, error)
	SetMaxID(key string, firstID, maxID uint32) error

	GASNewL3n4AddrID(basePath string, baseID uint32, lAddrID *types.L3n4AddrID) error
	// END Obsolete API

	// Status returns the status of he kvstore client including an
	// eventual error
	Status() (string, error)

	// LockPath locks the provided path
	LockPath(path string) (kvLocker, error)

	// Get returns value of key
	Get(key string) ([]byte, error)

	// GetPrefix returns the first key which matches the prefix
	GetPrefix(prefix string) ([]byte, error)

	// Set sets value of key
	Set(key string, value []byte) error

	// Delete deletes a key
	Delete(key string) error

	DeletePrefix(path string) error

	// Update atomically creates a key or fails if it already exists
	Update(key string, value []byte, lease bool) error

	// CreateOnly atomically creates a key or fails if it already exists
	CreateOnly(key string, value []byte, lease bool) error

	// CreateIfExists creates a key with the value only if key condKey exists
	CreateIfExists(condKey, key string, value []byte, lease bool) error

	// ListPrefix returns a list of keys matching the prefix
	ListPrefix(prefix string) (KeyValuePairs, error)

	// Watch starts watching for changes in a prefix. If list is true, the
	// current keys matching the prefix will be listed and reported as new
	// keys first.
	Watch(w *Watcher)

	// CreateLease creates a lease with the specified ttl
	CreateLease(ttl time.Duration) (interface{}, error)

	// KeepAlive keeps a lease previously created with CreateLease alive
	// for the duration specified at CreateLease time
	KeepAlive(lease interface{}) error

	// DeleteLease deletes a lease
	DeleteLease(interface{}) error

	// Close closes the kvstore client
	Close()

	// GetCapabilities returns the capabilities of the backend
	GetCapabilities() Capabilities

	// Encodes a binary slice into a character set that the backend
	// supports
	Encode(in []byte) string

	// Decodes a key previously encoded back into the original binary slice
	Decode(in string) ([]byte, error)
}
