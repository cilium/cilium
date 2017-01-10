//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package policy

import (
	"crypto/sha512"
	"fmt"

	"github.com/cilium/cilium/pkg/labels"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-policy")
)

// Available privileges for policy nodes to define
type Privilege byte

const (
	ALLOW Privilege = iota
	ALWAYS_ALLOW
	REQUIRES
	L4
)

var (
	privEnc = map[Privilege]string{
		ALLOW:        "allow",
		ALWAYS_ALLOW: "always-allow",
		REQUIRES:     "requires",
		L4:           "l4",
	}
	privDec = map[string]Privilege{
		"allow":        ALLOW,
		"always-allow": ALWAYS_ALLOW,
		"requires":     REQUIRES,
		"l4":           L4,
	}
)

func (p Privilege) String() string {
	if v, exists := privEnc[p]; exists {
		return v
	}
	return ""
}

func (p *Privilege) UnmarshalJSON(b []byte) error {
	if p == nil {
		p = new(Privilege)
	}
	if len(b) <= len(`""`) {
		return fmt.Errorf("invalid privilege '%s'", string(b))
	}
	if v, exists := privDec[string(b[1:len(b)-1])]; exists {
		*p = Privilege(v)
		return nil
	}

	return fmt.Errorf("unknown '%s' privilege", string(b))
}

func (d Privilege) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, d)), nil
}

type ConsumableDecision byte

const (
	UNDECIDED ConsumableDecision = iota
	ACCEPT
	ALWAYS_ACCEPT
	DENY
)

var (
	cdEnc = map[ConsumableDecision]string{
		UNDECIDED:     "undecided",
		ACCEPT:        "accept",
		ALWAYS_ACCEPT: "always-accept",
		DENY:          "deny",
	}
	cdDec = map[string]ConsumableDecision{
		"undecided":     UNDECIDED,
		"accept":        ACCEPT,
		"always-accept": ALWAYS_ACCEPT,
		"deny":          DENY,
	}
)

type Tracing int

const (
	TRACE_DISABLED Tracing = iota
	TRACE_ENABLED
	TRACE_VERBOSE
)

func policyTrace(ctx *SearchContext, format string, a ...interface{}) {
	switch ctx.Trace {
	case TRACE_ENABLED, TRACE_VERBOSE:
		log.Debugf(format, a...)
		if ctx.Logging != nil {
			ctx.Logging.Logger.Printf(format, a...)
		}
	}
}

func policyTraceVerbose(ctx *SearchContext, format string, a ...interface{}) {
	switch ctx.Trace {
	case TRACE_VERBOSE:
		log.Debugf(format, a...)
		if ctx.Logging != nil {
			ctx.Logging.Logger.Printf(format, a...)
		}
	}
}

func (d ConsumableDecision) String() string {
	if v, exists := cdEnc[d]; exists {
		return v
	}
	return ""
}

func (d *ConsumableDecision) UnmarshalJSON(b []byte) error {
	if d == nil {
		d = new(ConsumableDecision)
	}
	if len(b) <= len(`""`) {
		return fmt.Errorf("invalid consumable decision '%s'", string(b))
	}
	if v, exists := cdDec[string(b[1:len(b)-1])]; exists {
		*d = ConsumableDecision(v)
		return nil
	}

	return fmt.Errorf("unknown '%s' consumable decision", string(b))
}

func (d ConsumableDecision) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, d)), nil
}

type SearchContext struct {
	Trace   Tracing
	Logging *logging.LogBackend
	// TODO: Put this as []*Label?
	From []labels.Label
	To   []labels.Label
}

type SearchContextReply struct {
	Logging  []byte
	Decision ConsumableDecision
}

func (s *SearchContext) TargetCoveredBy(coverage []labels.Label) bool {
	for k := range coverage {
		covLabel := &coverage[k]
		for k2 := range s.To {
			toLabel := &s.To[k2]
			if covLabel.Matches(toLabel) {
				return true
			}
		}
	}

	return false
}

var (
	CoverageSHASize = len(fmt.Sprintf("%x", sha512.New512_256().Sum(nil)))
)
