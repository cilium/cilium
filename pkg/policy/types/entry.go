// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "strconv"

type ListenerPriority uint8 // Lower values take precedence
type Priority uint32        // Lower values take precedence, only lower 24 bits are used

type Precedence uint32 // Higher values take precedence

const (
	MaxListenerPriority = 126

	precedencePriorityShift          = 8
	precedencePriorityBits           = 32 - precedencePriorityShift
	MaxPriority             Priority = 1<<precedencePriorityBits - 1

	// Precedence low byte values for entries on the same priority level (bytes 1-3)
	PrecedenceDeny  Precedence = 255 // all low 8 bits set
	PrecedenceAllow Precedence = 1   // Note: proxy redirects use higher values
	PrecedencePass  Precedence = 0

	MaxPrecedence         = ^Precedence(0)
	MaxDenyPrecedence     = MaxPrecedence
	MaxPriorityPrecedence = (MaxPrecedence & ^(PrecedenceDeny))
	MaxAllowPrecedence    = (MaxPrecedence & ^(PrecedenceDeny)) + PrecedenceAllow
)

func (p *Priority) IncrementWithRoundup(to Priority) bool {
	np := *p + 1
	np = ((np + (to - 1)) / to) * to
	if np > MaxPriority || np < *p {
		return false
	}
	*p = np
	return true
}

func (p *Priority) Add(add Priority) bool {
	np := *p + add
	if np > MaxPriority || np < *p {
		return false
	}
	*p = np
	return true
}

func (p Precedence) IsDeny() bool {
	return p&PrecedenceDeny == PrecedenceDeny
}

func (p Precedence) IsPass() bool {
	return p&PrecedenceDeny == PrecedencePass
}

func (p Precedence) IsAllow() bool {
	return !p.IsDeny() && !p.IsPass()
}

// ProxyPortPrecedenceMayDiffer returns true if the non-proxy port precedence bits are the same
func (p Precedence) ProxyPortPrecedenceMayDiffer(o Precedence) bool {
	return p^o <= PrecedenceDeny && p.IsDeny() == o.IsDeny()
}

func (p Precedence) Priority() Priority {
	return MaxPriority - Priority(p>>precedencePriorityShift)
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

	invalid bool

	// AuthRequirement is non-zero when authentication is required for the traffic to be
	// allowed, except for when it explicitly defines authentication is not required.
	AuthRequirement AuthRequirement

	// Cookie is the policy log cookie. It is non-zero, datapath will pass up the cookie on any
	// policy verdict.
	Cookie uint32
}

type MapStateMap map[Key]MapStateEntry

func (e *MapStateEntry) Invalidate() {
	e.invalid = true
}

func (e MapStateEntry) IsValid() bool {
	return !e.invalid
}

// String returns a string representation of the MapStateEntry
func (e MapStateEntry) String() string {
	priority := MaxPriority - Priority(e.Precedence>>precedencePriorityShift)
	listenerPriority := ListenerPriority(PrecedenceDeny - (e.Precedence & PrecedenceDeny))

	verdict := "allow"
	if e.IsDeny() {
		verdict = "deny"
	}
	if !e.IsValid() {
		verdict = "invalid"
	}
	verdictText := "Verdict=" + verdict

	var proxyText string
	if e.ProxyPort != 0 {
		proxyText = ",ProxyPort=" + strconv.FormatUint(uint64(e.ProxyPort), 10)
	}

	priorityText := ",Priority=" + strconv.FormatUint(uint64(priority), 10) +
		":" + strconv.FormatUint(uint64(listenerPriority), 10)

	var authText string
	if e.AuthRequirement != 0 {
		var authNote string
		if !e.AuthRequirement.IsExplicit() {
			authNote = " (derived)"
		}
		authText = ",AuthType=" + e.AuthRequirement.AuthType().String() + authNote
	}

	var cookieText string
	if e.Cookie != 0 {
		cookieText = ",Cookie=" + strconv.FormatUint(uint64(e.Cookie), 10)
	}

	return verdictText + priorityText + proxyText + authText + cookieText
}

// Convert API priority to the lowest datapath Precedence for that priority:
//   - Priority is inverted (0 becomes the 1 << 24 - 1)
//   - Inverted priority is shifted to the upper bits in the 32-bit Precedence to make space for
//     the deny and proxy port precedence bits in the lower 8 bits.
//   - low 8 bits are left as zeroes
func (priority Priority) toBasePrecedence() Precedence {
	if priority > MaxPriority {
		priority = MaxPriority
	}
	return Precedence(MaxPriority-priority) << precedencePriorityShift
}

// PassPrecedence is the precedence with lower 8 bits cleared
func (priority Priority) ToPassPrecedence() Precedence {
	return priority.toBasePrecedence()
}

// NewMapStateEntry creeates a new MapStateEntry
// Lower incoming "API" priority and proxy port listener priority indicate higher precedence.
// The integrated 'Precedence' field has inverted semantics:
// - the higher numbers have higher precedence.
// - 'priority' gets shifted into the highest 24 bits of 'Precedence', inverted
// - 'verdict' deny status is also encoded into the PrecedenceDeny bit
// - Proxy port 'priority' is encoded in to the low 7 bits of 'Precedence', inverted
func NewMapStateEntry(
	priority Priority,
	deny bool,
	proxyPort uint16,
	listenerPriority ListenerPriority,
	authReq AuthRequirement,
) MapStateEntry {
	precedence := priority.toBasePrecedence()

	if deny {
		precedence += PrecedenceDeny

		// Normalize inputs
		proxyPort = 0
		listenerPriority = 0
		authReq = 0
	} else {
		precedence += PrecedenceAllow
	}

	return MapStateEntry{
		Precedence:      precedence,
		ProxyPort:       proxyPort,
		AuthRequirement: authReq,
	}.WithListenerPriority(listenerPriority)
}

func (e MapStateEntry) IsDeny() bool {
	return e.Precedence.IsDeny()
}

func (e MapStateEntry) IsAllow() bool {
	return e.Precedence.IsAllow()
}

// IsRedirectEntry returns true if the entry redirects to a proxy port
func (e MapStateEntry) IsRedirectEntry() bool {
	return e.ProxyPort != 0
}

// AllowPrecedence masks away the impact of redirect (priority) on the precedence
func (e MapStateEntry) AllowPrecedence() Precedence {
	return (e.Precedence & ^PrecedenceDeny) + PrecedenceAllow
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

// InvalidEntry returns an invalid MapStateEntry with max precedence that translates to 0 priority
func InvalidEntry() MapStateEntry {
	return MapStateEntry{invalid: true, Precedence: MaxDenyPrecedence}
}

// WithPriority is only used for testing
func (e MapStateEntry) WithPriority(priority Priority) MapStateEntry {
	e.Precedence &= 1<<precedencePriorityShift - 1 // clear all priority bits
	e.Precedence |= Precedence(MaxPriority-priority) << precedencePriorityShift
	return e
}

// WithDeny returns the entry 'e' with the precedence set to deny, or allow preserving proxy port
// precedence, if any, depending on the value of 'isDeny' parameter
func (e MapStateEntry) WithDeny(isDeny bool) MapStateEntry {
	if isDeny {
		if !e.Precedence.IsDeny() {
			e.Precedence |= PrecedenceDeny
		}
	} else if !e.Precedence.IsAllow() {
		e.Precedence &= ^PrecedenceDeny
		e.Precedence += PrecedenceAllow
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
//
// Note: Only to be called for allow entries where the low byte of the precedence field is
// initialized to PrecedenceAllow. Does nothing if proxy port is not set.
func (e MapStateEntry) WithListenerPriority(priority ListenerPriority) MapStateEntry {
	if e.ProxyPort != 0 {
		// (e.Precedence & PrecedenceDeny) == PrecedenceAllow
		if priority > 0 {
			priority = min(priority, MaxListenerPriority)

			// invert the priority so that higher number has the
			// precedence, priority 1 becomes 254, 100 -> 155, 126 -> 129
			// '255' is reserved for deny entries
			// '2' is reserved for a listener priority passed as 0
			// '1' is reserved for allow entries without proxy redirect
			// '0' is reserved for pass verdicts
			e.Precedence += PrecedenceDeny - 1 - Precedence(priority)
		} else {
			e.Precedence += 1 // proxy port without explicit priority
		}
	}
	return e
}

// WithProxyPort return the MapStateEntry with proxy port set at the default precedence
// Only used for testing
func (e MapStateEntry) WithProxyPort(proxyPort uint16) MapStateEntry {
	if proxyPort == 0 {
		panic("zero proxy port")
	}
	e.ProxyPort = proxyPort
	e.Precedence &= ^PrecedenceDeny
	e.Precedence += PrecedenceAllow // base allow priority, to be updated via WithListenerPriority()
	return e
}

// Merge is only called for entries whose precedence may differ only for the proxy port priority
// value.
func (e *MapStateEntry) Merge(entry MapStateEntry) {
	// Only allow entries have proxy redirection or auth requirement
	if e.IsAllow() && entry.IsAllow() {
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
