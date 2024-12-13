// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "strconv"

type ProxyPortPriority uint8

const (
	MaxProxyPortPriority = 255
	MaxListenerPriority  = 100
)

// MapStateEntry is the configuration associated with a Key in a
// MapState. This is a minimized version of policymap.PolicyEntry.
type MapStateEntry struct {
	// isDeny is true when the policy should be denied.
	isDeny bool

	// ProxyPortPriority encodes the listener priority.
	ProxyPortPriority ProxyPortPriority

	// The proxy port, in host byte order.
	// If 0 (default), there is no proxy redirection for the corresponding
	// Key. Any other value signifies proxy redirection.
	ProxyPort uint16

	// Invalid is only set to mark the current entry for update when syncing entries to datapath
	Invalid bool

	// AuthRequirement is non-zero when authentication is required for the traffic to be
	// allowed, except for when it explicitly defines authentication is not required.
	AuthRequirement AuthRequirement
}

// String returns a string representation of the MapStateEntry
func (e MapStateEntry) String() string {
	var authText string
	if e.AuthRequirement != 0 {
		var authNote string
		if !e.AuthRequirement.IsExplicit() {
			authNote = " (derived)"
		}
		authText = ",AuthType=" + e.AuthRequirement.AuthType().String() + authNote
	}

	return "IsDeny=" + strconv.FormatBool(e.IsDeny()) +
		",ProxyPort=" + strconv.FormatUint(uint64(e.ProxyPort), 10) +
		",Priority=" + strconv.FormatUint(uint64(e.ProxyPortPriority), 10) +
		authText
}

// NewMapStateEntry creeates a new MapStateEntry
// Listener 'priority' is encoded in ProxyPortPriority, inverted
func NewMapStateEntry(deny bool, proxyPort uint16, priority uint8, authReq AuthRequirement) MapStateEntry {
	// Normalize inputs
	if deny {
		proxyPort = 0
		priority = 0
		authReq = 0
	}
	return MapStateEntry{
		isDeny:          deny,
		ProxyPort:       proxyPort,
		AuthRequirement: authReq,
	}.WithProxyPriority(priority)
}

func (e MapStateEntry) IsDeny() bool {
	return e.isDeny
}

// IsRedirectEntry returns true if the entry redirects to a proxy port
func (e MapStateEntry) IsRedirectEntry() bool {
	return e.ProxyPort != 0
}

// AllowEntry returns a MapStateEntry for an allow policy without a proxy redirect
func AllowEntry() MapStateEntry {
	return MapStateEntry{}
}

// DenyEntry returns a MapStateEntry for a deny policy
func DenyEntry() MapStateEntry {
	return MapStateEntry{isDeny: true}
}

// WithDeny returns the entry 'e' with 'isDeny' set as indicated
func (e MapStateEntry) WithDeny(isDeny bool) MapStateEntry {
	e.isDeny = isDeny
	return e
}

// WithProxyPriority returns a MapStateEntry with the given listener priority:
// 0 - default (low) priority for all proxy redirects
// 1 - highest listener priority
// ..
// 100 - lowest (non-default) listener priority
func (e MapStateEntry) WithProxyPriority(priority uint8) MapStateEntry {
	if e.ProxyPort != 0 {
		if priority > 0 {
			priority = min(priority, MaxListenerPriority)

			// invert the priority so that higher number has the
			// precedence, priority 1 becomes 254, 100 -> 155
			e.ProxyPortPriority = MaxProxyPortPriority - ProxyPortPriority(priority)
		} else {
			e.ProxyPortPriority = 1 // proxy port without explicit priority
		}
	}
	return e
}

// WithProxyPort return the MapStateEntry with proxy port set at the default precedence
func (e MapStateEntry) WithProxyPort(proxyPort uint16) MapStateEntry {
	e.ProxyPort = proxyPort
	e.ProxyPortPriority = 1 // proxy port without explicit priority
	return e
}

// Merge is only called if both entries are denies or allows
func (e *MapStateEntry) Merge(entry MapStateEntry) {
	// Only allow entries have proxy redirection or auth requirement
	if !e.IsDeny() {
		// Proxy port takes precedence, but may be updated due to priority
		if entry.IsRedirectEntry() {
			// Higher number has higher priority, but non-redirects have 0 priority
			// value.
			// Proxy port value is the tie-breaker when priorities have the same value.
			if entry.ProxyPortPriority > e.ProxyPortPriority || entry.ProxyPortPriority == e.ProxyPortPriority && entry.ProxyPort < e.ProxyPort {
				e.ProxyPort = entry.ProxyPort
				e.ProxyPortPriority = entry.ProxyPortPriority
			}
		}

		// Numerically higher AuthType takes precedence when both are
		// either explicitly defined or derived
		if entry.AuthRequirement.IsExplicit() == e.AuthRequirement.IsExplicit() {
			if entry.AuthRequirement > e.AuthRequirement {
				e.AuthRequirement = entry.AuthRequirement
			}
		} else if entry.AuthRequirement.IsExplicit() {
			// Explicit auth takes precedence over defaulted one.
			e.AuthRequirement = entry.AuthRequirement
		}
	}
}
