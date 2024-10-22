// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"regexp"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// maxSyncErrors is the maximum consecutive errors syncing before the
	// controller bails out
	maxSyncErrors = 512

	// errorResolverSchedulerMinInterval is the minimum interval for the
	// error resolver to be scheduled. This minimum interval ensures not to
	// overschedule if a large number of updates fail in a row.
	errorResolverSchedulerMinInterval = 5 * time.Second

	// errorResolverSchedulerDelay is the delay to update the controller
	// after determination that a run is needed. The delay allows to
	// schedule the resolver after series of updates have failed.
	errorResolverSchedulerDelay = 200 * time.Millisecond
)

var (
	mapControllers = controller.NewManager()
)

// DesiredAction is the action to be performed on the BPF map
type DesiredAction uint8

const (
	// OK indicates that to further action is required and the entry is in
	// sync
	OK DesiredAction = iota

	// Insert indicates that the entry needs to be created or updated
	Insert

	// Delete indicates that the entry needs to be deleted
	Delete
)

func (d DesiredAction) String() string {
	switch d {
	case OK:
		return "sync"
	case Insert:
		return "to-be-inserted"
	case Delete:
		return "to-be-deleted"
	default:
		return "unknown"
	}
}

var commonNameRegexps = []*regexp.Regexp{
	regexp.MustCompile(`^(cilium_)(.+)_reserved_[0-9]+$`),
	regexp.MustCompile(`^(cilium_)(.+)_netdev_ns_[0-9]+$`),
	regexp.MustCompile(`^(cilium_)(.+)_overlay_[0-9]+$`),
	regexp.MustCompile(`^(cilium_)(.+)_[0-9]+$`),
	regexp.MustCompile(`^(cilium_)(.+)+$`),
}

func extractCommonName(name string) string {
	for _, r := range commonNameRegexps {
		if replaced := r.ReplaceAllString(name, `$2`); replaced != name {
			return replaced
		}
	}

	return name
}
