// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/identity"
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

// hostAddr wraps netip.Addr with the semantics that the value being stored is
// a host where a peer with this prefix resides. Technically we could just
// store the netip.Addr directly in the resourceInfo and just assume it is the
// host of the peer prefix, but if we ever want to associate any other
// addresses with the prefix then we'd have to factor that out anyway. This
// makes the type more explicit at the expense of some extra verbosity / casts.
type hostAddr struct {
	netip.Addr
}

// resourceInfo is all of the information that has been collected from a given
// resource (types.ResourceID) about this IP. Each field must have a 'zero'
// value that indicates that it should be ignored for purposes of merging
// multiple resourceInfo across multiple ResourceIDs together.
type resourceInfo struct {
	// identity takes precedence over labels if it is non-nil.
	identity *identity.Identity
	labels   labels.Labels
	source   source.Source
	host     hostAddr
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
	case *identity.Identity:
		if m.identity != nil {
			log.WithFields(logrus.Fields{
				logfields.OldIdentity: m.identity,
				logfields.Identity:    info,
				logfields.URL:         "https://github.com/cilium/cilium/issues",
			}).Errorf("BUG: Prefix maps to multiple identities. Please report this issue.")
		}
		m.identity = info
	case hostAddr:
		if m.host.IsValid() {
			log.WithFields(logrus.Fields{
				logfields.IPAddr:   m.host,
				logfields.Identity: info,
				logfields.URL:      "https://github.com/cilium/cilium/issues",
			}).Errorf("BUG: Prefix maps to peer on multiple hosts. Please report this issue.")
		}
		m.host = info
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
	case *identity.Identity:
		m.identity = nil
	case hostAddr:
		m.host = hostAddr{netip.Addr{}}
	default:
		log.Errorf("BUG: Invalid IPMetadata passed to ipinfo.unmerge(): %+v", info)
		return
	}
}

func (m *resourceInfo) isValid() bool {
	return m.identity != nil || m.labels != nil
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
	// TODO: Actually we should probably just return an error here,
	//       Then force the caller to pick the identity directly
	//       This way, the identity reference counting can be entirely
	//       external to the ipcache metadata map. This helps callers
	//       understand when to remove the entry from the ipcache map,
	//       otherwise you either:
	//       - Add an extra identity allocation for the direct identity,
	//         meaning that callers cannot decide when they are the "last"
	//         user of the identity, or
	//       - Trigger the regular "release the old identity" logic in the
	//         main TriggerLabelInjection() loop, thereby dropping the
	//         reference count below zero (which is probably bad?)
	//       ... The worst danger is some combination where the main loop
	//       resolves the labels to that identity via this logic, thereby
	//       adding a reference which can never be decremented because the
	//       callers remove from the metadata map based on identity refs
	for _, v := range s {
		if v.identity != nil {
			l.MergeLabels(v.labels)
			return l
		}
	}
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

func (s prefixInfo) Host() netip.Addr {
	for _, v := range s {
		if v.host.IsValid() {
			return v.host.Addr
		}
	}
	return netip.Addr{}
}
