// Copyright 2016-2018 Authors of Cilium
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

package identity

import (
	"errors"
	"strconv"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	// MinimalNumericIdentity represents the minimal numeric identity not
	// used for reserved purposes.
	MinimalNumericIdentity = NumericIdentity(256)

	// UserReservedNumericIdentity represents the minimal numeric identity that
	// can be used by users for reserved purposes.
	UserReservedNumericIdentity = NumericIdentity(128)

	// InvalidIdentity is the identity assigned if the identity is invalid
	// or not determined yet
	InvalidIdentity = NumericIdentity(0)
)

const (
	// IdentityUnknown represents an unknown identity
	IdentityUnknown NumericIdentity = iota

	// ReservedIdentityHost represents the local host
	ReservedIdentityHost

	// ReservedIdentityWorld represents any endpoint outside of the cluster
	ReservedIdentityWorld

	// ReservedIdentityCluster represents any endpoint inside the cluster
	// that does not have a more specific identity
	ReservedIdentityCluster

	// ReservedIdentityHealth represents the local cilium-health endpoint
	ReservedIdentityHealth

	// ReservedIdentityInit is the identity given to endpoints that have not
	// received any labels yet.
	ReservedIdentityInit
)

var (
	reservedIdentitiesMutex lock.RWMutex
	reservedIdentities      = map[string]NumericIdentity{
		labels.IDNameHost:    ReservedIdentityHost,
		labels.IDNameWorld:   ReservedIdentityWorld,
		labels.IDNameHealth:  ReservedIdentityHealth,
		labels.IDNameCluster: ReservedIdentityCluster,
		labels.IDNameInit:    ReservedIdentityInit,
	}
	reservedIdentityNames = map[NumericIdentity]string{
		ReservedIdentityHost:    labels.IDNameHost,
		ReservedIdentityWorld:   labels.IDNameWorld,
		ReservedIdentityHealth:  labels.IDNameHealth,
		ReservedIdentityCluster: labels.IDNameCluster,
		ReservedIdentityInit:    labels.IDNameInit,
	}

	// ErrNotUserIdentity is an error returned for an identity that is not user
	// reserved.
	ErrNotUserIdentity = errors.New("not a user reserved identity")
)

// IsUserReservedIdentity returns true if the given NumericIdentity belongs
// to the space reserved for users.
func IsUserReservedIdentity(id NumericIdentity) bool {
	return id.Uint32() >= UserReservedNumericIdentity.Uint32() &&
		id.Uint32() < MinimalNumericIdentity.Uint32()
}

// AddUserDefinedNumericIdentity adds the given numeric identity and respective
// label to the list of reservedIdentities. If the numeric identity is not
// between UserReservedNumericIdentity and MinimalNumericIdentity it will return
// ErrNotUserIdentity.
func AddUserDefinedNumericIdentity(identity NumericIdentity, label string) error {
	if !IsUserReservedIdentity(identity) {
		return ErrNotUserIdentity
	}
	reservedIdentitiesMutex.Lock()
	defer reservedIdentitiesMutex.Unlock()
	reservedIdentities[label] = identity
	reservedIdentityNames[identity] = label
	return nil
}

// DelReservedNumericIdentity deletes the given Numeric Identity from the list
// of reservedIdentities. If the numeric identity is not between
// UserReservedNumericIdentity and MinimalNumericIdentity it will return
// ErrNotUserIdentity.
func DelReservedNumericIdentity(identity NumericIdentity) error {
	if !IsUserReservedIdentity(identity) {
		return ErrNotUserIdentity
	}
	reservedIdentitiesMutex.Lock()
	defer reservedIdentitiesMutex.Unlock()
	label, ok := reservedIdentityNames[identity]
	if ok {
		delete(reservedIdentities, label)
		delete(reservedIdentityNames, identity)
	}
	return nil
}

// NumericIdentity is the numeric representation of a security identity / a
// security policy.
type NumericIdentity uint32

func ParseNumericIdentity(id string) (NumericIdentity, error) {
	nid, err := strconv.ParseUint(id, 0, 32)
	if err != nil {
		return NumericIdentity(0), err
	}
	return NumericIdentity(nid), nil
}

func (id NumericIdentity) StringID() string {
	return strconv.FormatUint(uint64(id), 10)
}

func (id NumericIdentity) String() string {
	reservedIdentitiesMutex.RLock()
	defer reservedIdentitiesMutex.RUnlock()
	if v, exists := reservedIdentityNames[id]; exists {
		return v
	}

	return id.StringID()
}

// Uint32 normalizes the ID for use in BPF program.
func (id NumericIdentity) Uint32() uint32 {
	return uint32(id)
}

func GetReservedID(name string) NumericIdentity {
	reservedIdentitiesMutex.RLock()
	defer reservedIdentitiesMutex.RUnlock()
	if v, ok := reservedIdentities[name]; ok {
		return v
	}
	return IdentityUnknown
}

// IsReservedIdentity returns whether id is one of the special reserved identities.
func (id NumericIdentity) IsReservedIdentity() bool {
	reservedIdentitiesMutex.RLock()
	defer reservedIdentitiesMutex.RUnlock()
	_, isReservedIdentity := reservedIdentityNames[id]
	return isReservedIdentity
}

// ClusterID returns the cluster ID associated with the identity
func (id NumericIdentity) ClusterID() int {
	return int((uint32(id) >> 16) & 0xFF)
}

// GetAllReservedIdentities returns a list of all reserved numeric identities.
func GetAllReservedIdentities() []NumericIdentity {
	reservedIdentitiesMutex.RLock()
	defer reservedIdentitiesMutex.RUnlock()
	identities := []NumericIdentity{}
	for _, id := range reservedIdentities {
		identities = append(identities, id)
	}
	return identities
}

// IterateReservedIdentities iterates over all reservedIdentities and executes
// the given function for each key, value pair in reservedIdentities.
func IterateReservedIdentities(f func(key string, value NumericIdentity)) {
	reservedIdentitiesMutex.RLock()
	defer reservedIdentitiesMutex.RUnlock()
	for key, value := range reservedIdentities {
		f(key, value)
	}
}
