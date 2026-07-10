// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitymanager

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type IDManager interface {
	Add(identity *identity.Identity)
	Get(*identity.NumericIdentity) *identity.Identity
	GetAll() []*identity.Identity
	GetIdentityModels() []*models.IdentityEndpoints
	Remove(identity *identity.Identity)
	RemoveAll()
	RemoveOldAddNew(old *identity.Identity, new *identity.Identity)
	Subscribe(o Observer)
}

// IdentityManager caches information about a set of identities, currently a
// reference count of how many users there are for each identity.
type IdentityManager struct {
	logger     *slog.Logger
	mutex      lock.RWMutex
	identities map[identity.NumericIdentity]*identityMetadata
	observers  map[Observer]struct{}
}

// NewIDManager returns an initialized IdentityManager.
func NewIDManager(logger *slog.Logger) IDManager {
	return newIdentityManager(logger)
}

type identityMetadata struct {
	identity *identity.Identity
	refCount uint
}

func newIdentityManager(logger *slog.Logger) *IdentityManager {
	return &IdentityManager{
		logger:     logger,
		identities: make(map[identity.NumericIdentity]*identityMetadata),
		observers:  make(map[Observer]struct{}),
	}
}

// Add inserts the identity into the identity manager. If the identity is
// already in the identity manager, the reference count for the identity is
// incremented.
func (idm *IdentityManager) Add(identity *identity.Identity) {
	if identity == nil {
		return
	}

	idm.mutex.Lock()
	if idm.addLocked(identity) {
		idm.notifyObserversLocked(identity, true)
	}
	idm.mutex.Unlock()
}

func (idm *IdentityManager) addLocked(identity *identity.Identity) (added bool) {
	if identity == nil {
		return false
	}
	idMeta, exists := idm.identities[identity.ID]
	if !exists {
		idm.identities[identity.ID] = &identityMetadata{
			identity: identity,
			refCount: 1,
		}
		return true
	}
	idMeta.refCount++
	return false
}

// RemoveOldAddNew removes old from the identity manager and inserts new
// into the IdentityManager.
// Caller must have previously added the old identity with Add().
// This is a no-op if both identities have the same numeric ID.
func (idm *IdentityManager) RemoveOldAddNew(old, new *identity.Identity) {
	if old == nil && new == nil {
		return
	}
	// The host endpoint will always retain its reserved ID, but its labels may
	// change so we need to update its identity.
	if old != nil && new != nil && old.ID == new.ID && new.ID != identity.ReservedIdentityHost {
		return
	}

	idm.mutex.Lock()
	if idm.removeLocked(old) {
		idm.notifyObserversLocked(old, false)
	}
	if idm.addLocked(new) {
		idm.notifyObserversLocked(new, true)
	}
	idm.mutex.Unlock()
}

// RemoveAll removes all identities.
func (idm *IdentityManager) RemoveAll() {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()

	for id := range idm.identities {
		idm.removeLocked(idm.identities[id].identity)
	}
}

// Remove deletes the identity from the identity manager. If the identity is
// already in the identity manager, the reference count for the identity is
// decremented. If the identity is not in the cache, this is a no-op. If the
// ref count becomes zero, the identity is removed from the cache.
func (idm *IdentityManager) Remove(identity *identity.Identity) {
	if identity == nil {
		return
	}

	idm.mutex.Lock()
	if idm.removeLocked(identity) {
		idm.notifyObserversLocked(identity, false)
	}
	idm.mutex.Unlock()
}

func (idm *IdentityManager) notifyObserversLocked(identity *identity.Identity, added bool) {
	for o := range idm.observers {
		if added {
			o.LocalEndpointIdentityAdded(identity)
		} else {
			o.LocalEndpointIdentityRemoved(identity)
		}
	}
}
func (idm *IdentityManager) removeLocked(identity *identity.Identity) (removed bool) {
	if identity == nil {
		return
	}

	idm.logger.Debug(
		"Removing identity from identity manager",
		logfields.Identity, identity,
	)

	idMeta, exists := idm.identities[identity.ID]
	if !exists {
		idm.logger.Error(
			"removing identity not added to the identity manager!",
			logfields.Identity, identity,
		)
		return
	}
	idMeta.refCount--
	if idMeta.refCount == 0 {
		delete(idm.identities, identity.ID)
		removed = true
	}
	return
}

// Get returns the full identity based on the numeric identity. The returned
// identity is a pointer to a live object; do not modify!
func (idm *IdentityManager) Get(id *identity.NumericIdentity) *identity.Identity {
	if id == nil {
		return nil
	}

	idm.mutex.RLock()
	defer idm.mutex.RUnlock()

	idd, exists := idm.identities[*id]
	if !exists {
		return nil
	}
	return idd.identity
}

// GetAll returns all identities from the manager. The returned slices contains
// identities that are pointers to a live objects; do not modify!
func (idm *IdentityManager) GetAll() []*identity.Identity {
	idm.mutex.RLock()
	defer idm.mutex.RUnlock()
	ids := make([]*identity.Identity, 0, len(idm.identities))
	for _, v := range idm.identities {
		ids = append(ids, v.identity)
	}
	return ids
}

// GetIdentityModels returns the API representation of the IdentityManager.
func (idm *IdentityManager) GetIdentityModels() []*models.IdentityEndpoints {
	idm.mutex.RLock()
	defer idm.mutex.RUnlock()

	identities := make([]*models.IdentityEndpoints, 0, len(idm.identities))

	for _, v := range idm.identities {
		identities = append(identities, &models.IdentityEndpoints{
			Identity: model.CreateModel(v.identity),
			RefCount: int64(v.refCount),
		})
	}

	return identities
}

// Subscribe adds the specified Observer to the global identity manager, to be
// notified upon changes to local identity usage.
func (idm *IdentityManager) Subscribe(o Observer) {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()
	idm.observers[o] = struct{}{}
}

// IdentitiesModel is a wrapper so that we can implement the sort.Interface
// to sort the slice by ID
type IdentitiesModel []*models.IdentityEndpoints

// Less returns true if the element in index `i` is lower than the element
// in index `j`
func (s IdentitiesModel) Less(i, j int) bool {
	return s[i].Identity.ID < s[j].Identity.ID
}

func ScriptCmds(idm *IdentityManager) map[string]script.Cmd {
	return map[string]script.Cmd{
		"idm/list": script.Command(
			script.CmdUsage{
				Summary: "List all identities in the identity manager",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				var sb strings.Builder
				models := idm.GetIdentityModels()
				sb.WriteRune('[')
				for _, m := range models {
					sb.WriteString(strconv.FormatInt(m.Identity.ID, 10))
					sb.WriteRune(' ')
					sb.WriteRune('{')
					sb.WriteString(strings.Join([]string(m.Identity.Labels), ","))
					sb.WriteRune('}')
					sb.WriteRune(' ')
				}
				sb.WriteRune(']')
				sb.WriteRune('\n')

				return func(s *script.State) (stdout string, stderr string, err error) {
					return sb.String(), "", nil
				}, nil
			},
		),
	}
}
