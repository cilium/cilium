// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"bytes"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/types"
)

// prefixInfo holds all of the information (labels, etc.) about a given prefix
// independently based on the ResourceID of the origin of that information, and
// provides convenient accessors to consistently merge the stored information
// to generate ipcache output based on a range of inputs.
//
// Note that when making a copy of this object, resourceInfo is pointer which
// means it needs to be deep-copied via (*resourceInfo).DeepCopy().
type prefixInfo map[ipcachetypes.ResourceID]*resourceInfo

// IdentityOverride can be used to override the identity of a given prefix.
// Must be provided together with a set of labels. Any other labels associated
// with this prefix are ignored while an override is present.
// This type implements ipcache.IPMetadata
type overrideIdentity bool

// resourceInfo is all of the information that has been collected from a given
// resource (types.ResourceID) about this IP. Each field must have a 'zero'
// value that indicates that it should be ignored for purposes of merging
// multiple resourceInfo across multiple ResourceIDs together.
type resourceInfo struct {
	labels           labels.Labels
	source           source.Source
	identityOverride overrideIdentity

	tunnelPeer        ipcachetypes.TunnelPeer
	encryptKey        ipcachetypes.EncryptKey
	requestedIdentity ipcachetypes.RequestedIdentity
}

// IPMetadata is an empty interface intended to inform developers using the
// IPCache interface about which types are valid to be injected, and how to
// update this code, in particular the merge(),unmerge(),isValid() methods
// below.
//
// In an ideal world, we would use Constraints here but as of Go 1.18, these
// cannot be used in conjunction with methods, which is how the information
// gets injected into the IPCache.
type IPMetadata any

// namedPortMultiMapUpdater allows for mutation of the NamedPortMultiMap, which
// is otherwise read-only.
type namedPortMultiMapUpdater interface {
	types.NamedPortMultiMap
	Update(old, new types.NamedPortMap) (namedPortChanged bool)
}

// merge overwrites the field in 'resourceInfo' corresponding to 'info'. This
// associates the new information with the prefix and ResourceID that this
// 'resourceInfo' resides under in the outer metadata map.
//
// returns true if the metadata was changed
func (m *resourceInfo) merge(info IPMetadata, src source.Source) bool {
	changed := false
	switch info := info.(type) {
	case labels.Labels:
		changed = !info.DeepEqual(&m.labels)
		m.labels = labels.NewFrom(info)
	case overrideIdentity:
		changed = m.identityOverride != info
		m.identityOverride = info
	case ipcachetypes.TunnelPeer:
		changed = m.tunnelPeer != info
		m.tunnelPeer = info
	case ipcachetypes.EncryptKey:
		changed = m.encryptKey != info
		m.encryptKey = info
	case ipcachetypes.RequestedIdentity:
		changed = m.requestedIdentity != info
		m.requestedIdentity = info
	default:
		log.Errorf("BUG: Invalid IPMetadata passed to ipinfo.merge(): %+v", info)
		return false
	}
	changed = changed || m.source != src
	m.source = src

	return changed
}

// unmerge removes the info of the specified type from 'resourceInfo'.
func (m *resourceInfo) unmerge(info IPMetadata) {
	switch info.(type) {
	case labels.Labels:
		m.labels = nil
	case overrideIdentity:
		m.identityOverride = false
	case ipcachetypes.TunnelPeer:
		m.tunnelPeer = ipcachetypes.TunnelPeer{}
	case ipcachetypes.EncryptKey:
		m.encryptKey = ipcachetypes.EncryptKeyEmpty
	case ipcachetypes.RequestedIdentity:
		m.requestedIdentity = ipcachetypes.RequestedIdentity(identity.IdentityUnknown)
	default:
		log.Errorf("BUG: Invalid IPMetadata passed to ipinfo.unmerge(): %+v", info)
		return
	}
}

func (m *resourceInfo) isValid() bool {
	if m.labels != nil {
		return true
	}
	if m.identityOverride {
		return true
	}
	if m.tunnelPeer.IsValid() {
		return true
	}
	if m.encryptKey.IsValid() {
		return true
	}
	if m.requestedIdentity.IsValid() {
		return true
	}
	return false
}

func (m *resourceInfo) DeepCopy() *resourceInfo {
	n := new(resourceInfo)
	n.labels = labels.NewFrom(m.labels)
	n.source = m.source
	n.identityOverride = m.identityOverride
	n.tunnelPeer = m.tunnelPeer
	n.encryptKey = m.encryptKey
	n.requestedIdentity = m.requestedIdentity
	return n
}

func (s prefixInfo) isValid() bool {
	for _, v := range s {
		if v.isValid() {
			return true
		}
	}
	return false
}

func (s prefixInfo) sortedBySourceThenResourceID() []ipcachetypes.ResourceID {
	return slices.SortedStableFunc(maps.Keys(s), func(a ipcachetypes.ResourceID, b ipcachetypes.ResourceID) int {
		if s[a].source != s[b].source {
			if !source.AllowOverwrite(s[a].source, s[b].source) {
				return -1
			} else {
				return 1
			}
		}
		return strings.Compare(string(a), string(b))
	})
}

func (s prefixInfo) ToLabels() labels.Labels {
	l := labels.NewLabelsFromModel(nil)
	for _, v := range s {
		l.MergeLabels(v.labels)
	}
	return l
}

func (s prefixInfo) Source() source.Source {
	src := source.Unspec
	for _, v := range s {
		if source.AllowOverwrite(src, v.source) {
			src = v.source
		}
	}
	return src
}

func (s prefixInfo) EncryptKey() ipcachetypes.EncryptKey {
	for _, rid := range s.sortedBySourceThenResourceID() {
		if k := s[rid].encryptKey; k.IsValid() {
			return k
		}
	}
	return ipcachetypes.EncryptKeyEmpty
}

func (s prefixInfo) TunnelPeer() ipcachetypes.TunnelPeer {
	for _, rid := range s.sortedBySourceThenResourceID() {
		if t := s[rid].tunnelPeer; t.IsValid() {
			return t
		}
	}
	return ipcachetypes.TunnelPeer{}
}

func (s prefixInfo) RequestedIdentity() ipcachetypes.RequestedIdentity {
	for _, rid := range s.sortedBySourceThenResourceID() {
		if id := s[rid].requestedIdentity; id.IsValid() {
			return id
		}
	}
	return ipcachetypes.RequestedIdentity(identity.InvalidIdentity)
}

// identityOverride extracts the labels of the pre-determined identity from
// the prefix info. If no override identity is present, this returns nil.
// This pre-determined identity will overwrite any other identity which may
// be derived from the prefix labels.
func (s prefixInfo) identityOverride() (lbls labels.Labels, hasOverride bool) {
	identities := make([]labels.Labels, 0, 1)
	for _, info := range s {
		// We emit a warning in logConflicts if an identity override
		// was requested without labels
		if info.identityOverride && len(info.labels) > 0 {
			identities = append(identities, info.labels)
		}
	}

	// No override identity present
	if len(identities) == 0 {
		return nil, false
	}

	// Conflict-resolution: We pick the labels with the alphabetically
	// lowest value when formatted in the KV store format. The conflict
	// is logged below in logConflicts.
	if len(identities) > 1 {
		sort.Slice(identities, func(i, j int) bool {
			a := identities[i].SortedList()
			b := identities[j].SortedList()
			return bytes.Compare(a, b) == -1
		})
	}

	return identities[0], true
}

func (s prefixInfo) logConflicts(scopedLog *logrus.Entry) {
	var (
		override           labels.Labels
		overrideResourceID ipcachetypes.ResourceID

		tunnelPeer           ipcachetypes.TunnelPeer
		tunnelPeerResourceID ipcachetypes.ResourceID

		encryptKey           ipcachetypes.EncryptKey
		encryptKeyResourceID ipcachetypes.ResourceID

		requestedID           ipcachetypes.RequestedIdentity
		requestedIDResourceID ipcachetypes.ResourceID
	)

	for _, resourceID := range s.sortedBySourceThenResourceID() {
		info := s[resourceID]

		if info.identityOverride {
			if len(override) > 0 {
				scopedLog.WithFields(logrus.Fields{
					logfields.Identity:            override.String(),
					logfields.Resource:            overrideResourceID,
					logfields.ConflictingIdentity: info.labels.String(),
					logfields.ConflictingResource: resourceID,
				}).Warning("Detected conflicting identity override for prefix. " +
					"This may cause connectivity issues for this address.")
			}

			if len(info.labels) == 0 {
				scopedLog.WithFields(logrus.Fields{
					logfields.Resource:    resourceID,
					logfields.OldIdentity: s.ToLabels().String(),
				}).Warning("Detected identity override, but no labels where specified. " +
					"Falling back on the old non-override labels. " +
					"This may cause connectivity issues for this address.")
			} else {
				override = info.labels
				overrideResourceID = resourceID
			}
		}

		if info.tunnelPeer.IsValid() {
			if tunnelPeer.IsValid() {
				if option.Config.TunnelingEnabled() {
					scopedLog.WithFields(logrus.Fields{
						logfields.TunnelPeer:            tunnelPeer.String(),
						logfields.Resource:              tunnelPeerResourceID,
						logfields.ConflictingTunnelPeer: info.tunnelPeer.String(),
						logfields.ConflictingResource:   resourceID,
					}).Warning("Detected conflicting tunnel peer for prefix. " +
						"This may cause connectivity issues for this address.")
				}
			} else {
				tunnelPeer = info.tunnelPeer
				tunnelPeerResourceID = resourceID
			}
		}

		if info.encryptKey.IsValid() {
			if encryptKey.IsValid() {
				scopedLog.WithFields(logrus.Fields{
					logfields.Key:                 encryptKey.String(),
					logfields.Resource:            encryptKeyResourceID,
					logfields.ConflictingKey:      info.encryptKey.String(),
					logfields.ConflictingResource: resourceID,
				}).Warning("Detected conflicting encryption key index for prefix. " +
					"This may cause connectivity issues for this address.")
			} else {
				encryptKey = info.encryptKey
				encryptKeyResourceID = resourceID
			}
		}

		if info.requestedIdentity.IsValid() {
			if requestedID.IsValid() {
				scopedLog.WithFields(logrus.Fields{
					logfields.Identity:            requestedID,
					logfields.Resource:            requestedIDResourceID,
					logfields.ConflictingKey:      info.requestedIdentity,
					logfields.ConflictingResource: resourceID,
				}).Warning("Detected conflicting requested numeric identity for prefix. " +
					"This may cause momentary connectivity issues for this address.")
			} else {
				requestedID = info.requestedIdentity
				requestedIDResourceID = resourceID
			}
		}
	}
}
