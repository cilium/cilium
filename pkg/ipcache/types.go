// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
	"github.com/sirupsen/logrus"
)

// prefixInfo holds all of the information (labels, etc.) about a given prefix
// independently based on the ResourceID of the origin of that information, and
// provides convenient accessors to consistently merge the stored information
// to generate ipcache output based on a range of inputs.
type prefixInfo map[types.ResourceID]*resourceInfo

// resourceInfo is all of the information that has been collected from a given
// resource (types.ResourceID) about this IP. Each field must have a 'zero'
// value that indicates that it should be ignored for purposes of merging
// multiple resourceInfo across multiple ResourceIDs together.
type resourceInfo struct {
	labels     labels.Labels
	EncryptKey *types.EncryptKey
	TunnelPeer types.TunnelPeer
	source     source.Source
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

// merge overwrites the field in 'resourceInfo' corresponding to 'info'. This
// associates the new information with the prefix and ResourceID that this
// 'resourceInfo' resides under in the outer metadata map.
func (m *resourceInfo) merge(info IPMetadata, src source.Source) {
	switch info := info.(type) {
	case labels.Labels:
		l := labels.NewLabelsFromModel(nil)
		l.MergeLabels(info)
		m.labels = l
	case types.EncryptKey:
		m.EncryptKey = &info
	case types.TunnelPeer:
		m.TunnelPeer = info
	default:
		log.Errorf("BUG: Invalid IPMetadata passed to ipinfo.merge(): %+v", info)
		return
	}
	m.source = src
}

// unmerge removes the info of the specified type from 'resourceInfo'.
func (m *resourceInfo) unmerge(info IPMetadata) {
	switch info.(type) {
	case labels.Labels:
		m.labels = nil
	case types.EncryptKey:
		m.EncryptKey = nil
	case types.TunnelPeer:
		m.TunnelPeer = ""
	default:
		log.Errorf("BUG: Invalid IPMetadata passed to ipinfo.unmerge(): %+v", info)
		return
	}
}

func (m *resourceInfo) isValid() bool {
	if m.labels != nil {
		return true
	}
	if m.EncryptKey != nil {
		return true
	}
	if m.TunnelPeer != "" {
		return true
	}
	return false
}

func (s prefixInfo) isValid() bool {
	for _, v := range s {
		if v.isValid() {
			return true
		}
	}
	return false
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

func (s prefixInfo) EncryptKey(prefix string) uint8 {
	var (
		key         types.EncryptKey
		keyResource types.ResourceID
	)
	for resource, v := range s {
		if v.EncryptKey != nil {
			if key != types.EncryptKey(0) {
				log.WithFields(logrus.Fields{
					logfields.CIDR:                prefix,
					logfields.Key:                 key,
					logfields.Resource:            keyResource,
					logfields.ConflictingKey:      *v.EncryptKey,
					logfields.ConflictingResource: resource,
				}).Warning("Detected conflicting encrypt-key for prefix")
			}
			key = *v.EncryptKey
			keyResource = resource
		}
	}
	return uint8(key)
}

func (s prefixInfo) TunnelPeer(prefix string) string {
	var (
		peer         types.TunnelPeer
		peerResource types.ResourceID
	)
	for resource, v := range s {
		if v.TunnelPeer != "" {
			if peer != "" {
				log.WithFields(logrus.Fields{
					logfields.CIDR:                prefix,
					logfields.Key:                 peer,
					logfields.Resource:            peerResource,
					logfields.ConflictingKey:      *v.EncryptKey,
					logfields.ConflictingResource: resource,
				}).Warning("Detected conflicting encrypt-key for prefix")
			}
			peer = v.TunnelPeer
			peerResource = resource
			break
		}
	}
	return string(peer)
}
