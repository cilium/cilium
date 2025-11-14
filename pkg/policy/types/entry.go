// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "strconv"

type ListenerPriority uint8
type Precedence uint32

const (
	PrecedenceDeny              Precedence = 1 << 7
	PrecedenceProxyPriorityMask Precedence = PrecedenceDeny - 1 // 0-127
	MaxListenerPriority                    = 126
	MaxPrecedence                          = ^Precedence(0)
	MaxDenyPrecedence                      = MaxPrecedence
	MaxAllowPrecedence                     = MaxPrecedence & ^(PrecedenceDeny | PrecedenceProxyPriorityMask)
)

// ProxyPortPrecedenceMayDiffer returns true if the non-proxy port precedence bits are the same
func (p Precedence) ProxyPortPrecedenceMayDiffer(o Precedence) bool {
	return p^o < PrecedenceDeny
}

// MapStateEntry is the configuration associated with a Key in a
// MapState. This is a minimized version of policymap.PolicyEntry.
type MapStateEntry struct {
	// Precedence encodes the relative order in which policy entries are selected
	// Higher values have higher precedence.
	// Deny and Listener priority are encoded into the precedence field.
	Precedence Precedence

	// The proxy port, in host byte order.
	// If 0 (default), there is no proxy redirection for the corresponding
	// Key. Any other value signifies proxy redirection.
	ProxyPort uint16

	// Invalid is only set to mark the current entry for update when syncing entries to datapath
	Invalid bool

	// AuthRequirement is non-zero when authentication is required for the traffic to be
	// allowed, except for when it explicitly defines authentication is not required.
	AuthRequirement AuthRequirement

	// Cookie is the policy log cookie. It is non-zero, datapath will pass up the cookie on any
	// policy verdict.
	Cookie uint32
}

type MapStateMap map[Key]MapStateEntry

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

	return "Precedence=" + strconv.FormatUint(uint64(e.Precedence), 10) +
		",ProxyPort=" + strconv.FormatUint(uint64(e.ProxyPort), 10) +
		",IsDeny=" + strconv.FormatBool(e.IsDeny()) +
		authText +
		",Cookie=" + strconv.FormatUint(uint64(e.Cookie), 10)
}

// NewMapStateEntry creates a new MapStateEntry
// 'deny' is encoded into the PrecedenceDeny bit
// Listener 'priority' is encoded in to the low 7 bits of 'precedence', inverted
func NewMapStateEntry(
	deny bool,
	proxyPort uint16,
	priority ListenerPriority,
	authReq AuthRequirement,
) MapStateEntry {
	// Normalize inputs
	if deny {
		proxyPort = 0
		priority = 0
		authReq = 0
	}
	// start from the highest precedence level so that datapath can skip L4 policy match if
	// L3-policy is a deny.
	precedence := MaxPrecedence
	if !deny {
		precedence &= ^(PrecedenceDeny | PrecedenceProxyPriorityMask)
	}
	return MapStateEntry{
		Precedence:      precedence,
		ProxyPort:       proxyPort,
		AuthRequirement: authReq,
	}.WithListenerPriority(priority)
}

func (e MapStateEntry) IsDeny() bool {
	return e.Precedence&PrecedenceDeny != 0
}

// IsRedirectEntry returns true if the entry redirects to a proxy port
func (e MapStateEntry) IsRedirectEntry() bool {
	return e.ProxyPort != 0
}

// AllowPrecedence masks away the impact of redirect (priority) on the precedence
func (e MapStateEntry) AllowPrecedence() Precedence {
	return e.Precedence & ^PrecedenceProxyPriorityMask
}

// AllowEntry returns a MapStateEntry with maximum precedence for an allow entry without a proxy
// redirect
func AllowEntry() MapStateEntry {
	return MapStateEntry{Precedence: MaxAllowPrecedence}
}

// DenyEntry returns a MapStateEntry with maximum precedence for a deny entry
func DenyEntry() MapStateEntry {
	return MapStateEntry{Precedence: MaxDenyPrecedence}
}

// WithDeny returns the entry 'e' with the precedence set to deny, or allow preserving proxy port
// precedence, if any, depending on the value of 'isDeny' parameter
func (e MapStateEntry) WithDeny(isDeny bool) MapStateEntry {
	if isDeny {
		e.Precedence |= PrecedenceDeny
	} else {
		e.Precedence &= ^PrecedenceDeny
	}
	return e
}

// WithListenerPriority returns a MapStateEntry with the given listener priority:
// 0 - default (low) priority for all proxy redirects
// 1 - highest listener priority
// ..
// 100 - lowest (non-default) listener priority
// 101 - priority for HTTP parser type
// 106 - priority for the Kafka parser type
// 111 - priority for the proxylib parsers
// 116 - priority for TLS interception parsers (can be promoted to HTTP/Kafka/proxylib)
// 121 - priority for DNS parser type
// 126 - default priority for CRD parser type
// 127 - reserved (listener priority passed as 0)
func (e MapStateEntry) WithListenerPriority(priority ListenerPriority) MapStateEntry {
	if e.ProxyPort != 0 {
		// Clear the proxy precedence bits
		e.Precedence &= ^(PrecedenceDeny | PrecedenceProxyPriorityMask)
		if priority > 0 {
			priority = min(priority, MaxListenerPriority)

			// invert the priority so that higher number has the
			// precedence, priority 1 becomes '127', 100 -> '28', 126 -> '2'
			// '1' is reserved for a listener priority passed as 0
			// '0' is reserved for entries without proxy redirect
			e.Precedence += PrecedenceProxyPriorityMask + 1 - Precedence(priority)
		} else {
			e.Precedence += 1 // proxy port without explicit priority
		}
	}
	return e
}

// WithProxyPort return the MapStateEntry with proxy port set at the default precedence
func (e MapStateEntry) WithProxyPort(proxyPort uint16) MapStateEntry {
	if proxyPort > 0 {
		e.ProxyPort = proxyPort
		e.Precedence &= ^(PrecedenceDeny | PrecedenceProxyPriorityMask)
		e.Precedence += 1 // proxy port without explicit priority
	}
	return e
}

// Merge is only called for entries whose precedence may differ only for the proxy port priority
// value.
func (e *MapStateEntry) Merge(entry MapStateEntry) {
	if entry.Precedence^e.Precedence >= PrecedenceDeny {
		panic("Merge called for incompatible entries")
	}
	// Only allow entries have proxy redirection or auth requirement
	if !e.IsDeny() {
		// Proxy port takes precedence, but may be updated due to priority
		if entry.IsRedirectEntry() {
			// Higher number has higher priority, but non-redirects have 0 priority
			// value.
			// Proxy port value is the tie-breaker when priorities have the same value.
			if entry.Precedence > e.Precedence || entry.Precedence == e.Precedence && entry.ProxyPort < e.ProxyPort {
				e.ProxyPort = entry.ProxyPort
				e.Precedence = entry.Precedence
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

// Diff returns the string of differences between 'obtained' and 'expected' prefixed with
// '+ ' or '- ' for obtaining something unexpected, or not obtaining the expected, respectively.
// For use in debugging from other packages.
func (obtained MapStateMap) Diff(expected MapStateMap) (res string) {
	res += "Missing (-), Unexpected (+):\n"
	for kE, vE := range expected {
		if vO, ok := obtained[kE]; ok {
			if vO != vE {
				res += "- " + kE.String() + ": " + vE.String() + "\n"
				res += "+ " + kE.String() + ": " + vO.String() + "\n"
			}
		} else {
			res += "- " + kE.String() + ": " + vE.String() + "\n"
		}
	}
	for kO, vO := range obtained {
		if _, ok := expected[kO]; !ok {
			res += "+ " + kO.String() + ": " + vO.String() + "\n"
		}
	}
	return res
}
