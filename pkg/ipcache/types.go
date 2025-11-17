// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"log/slog"
	"maps"
	"slices"
	"strings"

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
type prefixInfo struct {
	byResource map[ipcachetypes.ResourceID]*resourceInfo

	// flattened is the fully resolved information, with all information
	// by resource merged.
	flattened *resourceInfo
}

func newPrefixInfo() *prefixInfo {
	return &prefixInfo{
		byResource: make(map[ipcachetypes.ResourceID]*resourceInfo),
	}
}

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
	endpointFlags     ipcachetypes.EndpointFlags
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
func (m *resourceInfo) merge(logger *slog.Logger, info IPMetadata, src source.Source) bool {
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
	case ipcachetypes.EndpointFlags:
		changed = m.endpointFlags != info
		m.endpointFlags = info
	default:
		logger.Error(
			"BUG: Invalid IPMetadata passed to ipinfo.merge()",
			logfields.Info, info,
		)
		return false
	}
	changed = changed || m.source != src
	m.source = src

	return changed
}

// unmerge removes the info of the specified type from 'resourceInfo'.
func (m *resourceInfo) unmerge(logger *slog.Logger, info IPMetadata) {
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
	case ipcachetypes.EndpointFlags:
		m.endpointFlags = ipcachetypes.EndpointFlags{}
	default:
		logger.Error(
			"BUG: Invalid IPMetadata passed to ipinfo.unmerge()",
			logfields.Info, info,
		)
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
	if m.endpointFlags.IsValid() {
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
	n.endpointFlags = m.endpointFlags
	return n
}

func (s prefixInfo) isValid() bool {
	for _, v := range s.byResource {
		if v.isValid() {
			return true
		}
	}
	return false
}

func (s *prefixInfo) sortedBySourceThenResourceID() []ipcachetypes.ResourceID {
	return slices.SortedStableFunc(maps.Keys(s.byResource), func(a ipcachetypes.ResourceID, b ipcachetypes.ResourceID) int {
		if s.byResource[a].source != s.byResource[b].source {
			if !source.AllowOverwrite(s.byResource[a].source, s.byResource[b].source) {
				return -1
			} else {
				return 1
			}
		}
		return strings.Compare(string(a), string(b))
	})
}

func (r *resourceInfo) ToLabels() labels.Labels {
	if r.labels == nil {
		return labels.Labels{} // code expects non-nil Labels.
	}
	return r.labels
}

func (r *resourceInfo) Source() source.Source {
	if r == nil {
		return source.Unspec
	}
	return r.source
}

func (r *resourceInfo) EncryptKey() ipcachetypes.EncryptKey {
	if r == nil {
		return ipcachetypes.EncryptKeyEmpty
	}
	return r.encryptKey
}

func (r *resourceInfo) TunnelPeer() ipcachetypes.TunnelPeer {
	if r == nil {
		return ipcachetypes.TunnelPeer{}
	}
	return r.tunnelPeer
}

func (r *resourceInfo) RequestedIdentity() ipcachetypes.RequestedIdentity {
	if r == nil {
		return ipcachetypes.RequestedIdentity(identity.InvalidIdentity)
	}
	return r.requestedIdentity
}

func (r *resourceInfo) EndpointFlags() ipcachetypes.EndpointFlags {
	if r == nil {
		return ipcachetypes.EndpointFlags{}
	}
	return r.endpointFlags
}

// identityOverride returns true if the exact set of labels has been specified
// and should not be manipulated further.
func (r *resourceInfo) IdentityOverride() bool {
	if r == nil {
		return false
	}
	return bool(r.identityOverride)

}

// flatten resolves the set of all possible metadata in to a single
// flattened resource.
// In the event of a conflict, entries with a higher precedence source
// will win.
func (s *prefixInfo) flatten(scopedLog *slog.Logger) *resourceInfo {
	out := &resourceInfo{}

	var (
		overrideResourceID      ipcachetypes.ResourceID
		tunnelPeerResourceID    ipcachetypes.ResourceID
		encryptKeyResourceID    ipcachetypes.ResourceID
		requestedIDResourceID   ipcachetypes.ResourceID
		endpointFlagsResourceID ipcachetypes.ResourceID
	)

	labelResourceIDs := map[string]ipcachetypes.ResourceID{}

	for _, resourceID := range s.sortedBySourceThenResourceID() {
		info := s.byResource[resourceID]

		// Sorted by source priority, so the first source wins.
		if out.source == "" {
			out.source = info.source
		}

		if len(info.labels) > 0 && !out.identityOverride /* identityOverride already fixed the labels */ {
			if len(out.labels) > 0 {
				// merge labels, complaining if the value exists
				for key, newLabel := range info.labels {
					otherLabel, exists := out.labels[key]
					if exists && !otherLabel.DeepEqual(&newLabel) {
						scopedLog.Warn(
							"Detected conflicting label for prefix. "+
								"This may cause connectivity issues for this address.",
							logfields.Labels, out.labels,
							logfields.Resource, labelResourceIDs[key],
							logfields.ConflictingLabels, otherLabel,
						)
					} else if !exists {
						out.labels[key] = newLabel
						labelResourceIDs[key] = resourceID
					}
				}
			} else {
				out.labels = labels.NewFrom(info.labels) // copy map, as we will be mutating it
			}
		}

		if info.identityOverride {
			if len(info.labels) == 0 {
				scopedLog.Warn(
					"Detected identity override, but no labels where specified. "+
						"Falling back on the old non-override labels. "+
						"This may cause connectivity issues for this address.",
					logfields.Resource, resourceID,
				)
			} else {
				if out.identityOverride {
					scopedLog.Warn(
						"Detected conflicting identity override for prefix. "+
							"This may cause connectivity issues for this address.",
						logfields.Labels, out.labels,
						logfields.Resource, overrideResourceID,
						logfields.ConflictingLabels, info.labels,
						logfields.ConflictingResource, resourceID,
					)
				} else {
					out.identityOverride = true
					out.labels = info.labels
					overrideResourceID = resourceID
				}
			}
		}

		if info.tunnelPeer.IsValid() && info.tunnelPeer != out.tunnelPeer {
			if out.tunnelPeer.IsValid() {
				if option.Config.TunnelingEnabled() {
					scopedLog.Warn(
						"Detected conflicting tunnel peer for prefix. "+
							"This may cause connectivity issues for this address.",
						logfields.TunnelPeer, out.tunnelPeer,
						logfields.Resource, tunnelPeerResourceID,
						logfields.ConflictingTunnelPeer, info.tunnelPeer,
						logfields.ConflictingResource, resourceID,
					)
				}
			} else {
				out.tunnelPeer = info.tunnelPeer
				tunnelPeerResourceID = resourceID
			}
		}

		if info.encryptKey.IsValid() && info.encryptKey != out.encryptKey {
			if out.encryptKey.IsValid() {
				scopedLog.Warn(
					"Detected conflicting encryption key index for prefix. "+
						"This may cause connectivity issues for this address.",
					logfields.Key, out.encryptKey,
					logfields.Resource, encryptKeyResourceID,
					logfields.ConflictingKey, info.encryptKey,
					logfields.ConflictingResource, resourceID,
				)
			} else {
				out.encryptKey = info.encryptKey
				encryptKeyResourceID = resourceID
			}
		}

		if info.requestedIdentity.IsValid() && info.requestedIdentity != out.requestedIdentity {
			if out.requestedIdentity.IsValid() {
				scopedLog.Warn(
					"Detected conflicting requested numeric identity for prefix. "+
						"This may cause momentary connectivity issues for this address.",
					logfields.Identity, out.requestedIdentity,
					logfields.Resource, requestedIDResourceID,
					logfields.ConflictingIdentity, info.requestedIdentity,
					logfields.ConflictingResource, resourceID,
				)
			} else {
				out.requestedIdentity = info.requestedIdentity
				requestedIDResourceID = resourceID
			}
		}

		// Note: if more flags are added in pkg/ipcache/types/types.go,
		// they must be merged here.
		if info.endpointFlags.IsValid() && info.endpointFlags != out.endpointFlags {
			if out.endpointFlags.IsValid() {
				scopedLog.Warn(
					"Detected conflicting endpoint flags for prefix. "+
						"This may cause connectivity issues for this address.",
					logfields.EndpointFlags, out.endpointFlags,
					logfields.Resource, endpointFlagsResourceID,
					logfields.ConflictingEndpointFlags, info.endpointFlags,
					logfields.ConflictingResource, resourceID,
				)
			} else {
				out.endpointFlags = info.endpointFlags
				endpointFlagsResourceID = resourceID
			}
		}
	}

	return out
}
