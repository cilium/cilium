// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitymanager

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/labels"
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
	idm.logger.Debug(
		"Adding identity to identity manager",
		logfields.Identity, identity,
	)

	idm.mutex.Lock()
	idm.add(identity)
	idm.mutex.Unlock()

	for o := range idm.observers {
		o.LocalEndpointIdentityAdded(identity)
	}
}

func (idm *IdentityManager) add(identity *identity.Identity) {
	if identity == nil {
		return
	}

	idMeta, exists := idm.identities[identity.ID]
	if !exists {
		idm.identities[identity.ID] = &identityMetadata{
			identity: identity,
			refCount: 1,
		}
	} else {
		idMeta.refCount++
	}
}

// RemoveOldAddNew removes old from the identity manager and inserts new
// into the IdentityManager.
// Caller must have previously added the old identity with Add().
// This is a no-op if both identities have the same numeric ID.
func (idm *IdentityManager) RemoveOldAddNew(old, new *identity.Identity) {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()

	if old == nil && new == nil {
		return
	}
	// The host endpoint will always retain its reserved ID, but its labels may
	// change so we need to update its identity.
	if old != nil && new != nil && old.ID == new.ID && new.ID != identity.ReservedIdentityHost {
		return
	}

	idm.logger.Debug(
		"removing old and adding new identity",
		logfields.Old, old,
		logfields.New, new,
	)

	idm.remove(old)
	idm.add(new)
}

// RemoveAll removes all identities.
func (idm *IdentityManager) RemoveAll() {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()

	for id := range idm.identities {
		idm.remove(idm.identities[id].identity)
	}
}

// Remove deletes the identity from the identity manager. If the identity is
// already in the identity manager, the reference count for the identity is
// decremented. If the identity is not in the cache, this is a no-op. If the
// ref count becomes zero, the identity is removed from the cache.
func (idm *IdentityManager) Remove(identity *identity.Identity) {
	idm.logger.Debug(
		"Removing identity from identity manager",
		logfields.Identity, identity,
	)

	idm.mutex.Lock()
	idm.remove(identity)
	idm.mutex.Unlock()

	for o := range idm.observers {
		o.LocalEndpointIdentityRemoved(identity)
	}
}

func (idm *IdentityManager) remove(identity *identity.Identity) {
	if identity == nil {
		return
	}

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
	}
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
				Summary: "List all policies in the policy repository",
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
		"idm/add": script.Command(
			script.CmdUsage{
				Summary: "List all policies in the policy repository",
				Args:    "number labels",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				return func(s *script.State) (stdout string, stderr string, err error) {
					allArgs := []string(args)
					num, err := strconv.Atoi(allArgs[0])
					if err != nil {
						return "", "", fmt.Errorf("atoi: %w", err)
					}
					lstr := allArgs[1]

					var labelArr []labels.Label
					for s := range strings.SplitSeq(lstr, ",") {
						labelArr = append(labelArr, labels.ParseLabel(s))
					}

					idm.Add(&identity.Identity{
						ID:         identity.NumericIdentity(num),
						Labels:     labels.FromSlice(labelArr),
						LabelArray: labels.LabelArray(labelArr),
					})
					return "", "", nil
				}, nil
			},
		),
		"idm/add-from-stdout": script.Command(
			script.CmdUsage{
				Summary: "Add identity with the given labels and numeric value from stdout",
				Args:    "labels",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				var wait script.WaitFunc

				lines := slices.Collect(strings.Lines(s.Stdout()))
				if len(lines) != 1 {
					return wait, fmt.Errorf("expected stdout to contain only one line but got %v, see usage details", len(lines))
				}

				num, err := strconv.Atoi(strings.Trim(lines[0], "\n"))
				if err != nil {
					return wait, fmt.Errorf("atoi: %w", err)
				}

				lstr := []string(args)[0]
				var labelArr []labels.Label
				for _, s := range strings.Split(lstr, ",") {
					labelArr = append(labelArr, labels.ParseLabel(s))
				}

				idm.Add(&identity.Identity{
					ID:         identity.NumericIdentity(num),
					Labels:     labels.FromSlice(labelArr),
					LabelArray: labels.LabelArray(labelArr),
				})
				wait = func(s *script.State) (stdout string, stderr string, err error) {
					return "", "", nil
				}
				return wait, nil
			},
		),
	}
}
