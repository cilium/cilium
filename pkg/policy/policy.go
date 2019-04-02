// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"

	"github.com/op/go-logging"
)

type Tracing int

const (
	TRACE_DISABLED Tracing = iota
	TRACE_ENABLED
	TRACE_VERBOSE
)

// PolicyTrace logs the given message into the SearchContext logger only if
// TRACE_ENABLED or TRACE_VERBOSE is enabled in the receiver's SearchContext.
func (s *SearchContext) PolicyTrace(format string, a ...interface{}) {
	switch s.Trace {
	case TRACE_ENABLED, TRACE_VERBOSE:
		log.Debugf(format, a...)
		if s.Logging != nil {
			format = "%-" + s.CallDepth() + "s" + format
			a = append([]interface{}{""}, a...)
			s.Logging.Logger.Printf(format, a...)
		}
	}
}

// PolicyTraceVerbose logs the given message into the SearchContext logger only
// if TRACE_VERBOSE is enabled in the receiver's SearchContext.
func (s *SearchContext) PolicyTraceVerbose(format string, a ...interface{}) {
	switch s.Trace {
	case TRACE_VERBOSE:
		log.Debugf(format, a...)
		if s.Logging != nil {
			s.Logging.Logger.Printf(format, a...)
		}
	}
}

// SearchContext defines the context while evaluating policy
type SearchContext struct {
	Trace   Tracing
	Depth   int
	Logging *logging.LogBackend
	From    labels.LabelArray
	To      labels.LabelArray
	DPorts  []*models.Port
	// rulesSelect specifies whether or not to check whether a rule which is
	// being analyzed using this SearchContext matches either From or To.
	// This is used to avoid using EndpointSelector.Matches() if possible,
	// since it is costly in terms of performance.
	rulesSelect bool
	// skipL4RequirementsAggregation allows for skipping of aggregation of
	// requirements in L4 policy parsing, as it is expensive. This is used
	// when the policy is being calculated for an endpoint (vs. a trace),
	// and the set of denied identities can be consulted for when the PolicyMap
	// state is computed for an endpoint.
	skipL4RequirementsAggregation bool
}

func (s *SearchContext) String() string {
	from := []string{}
	to := []string{}
	dports := []string{}
	for _, fromLabel := range s.From {
		from = append(from, fromLabel.String())
	}
	for _, toLabel := range s.To {
		to = append(to, toLabel.String())
	}
	for _, dport := range s.DPorts {
		dports = append(dports, fmt.Sprintf("%d/%s", dport.Port, dport.Protocol))
	}
	ret := fmt.Sprintf("From: [%s]", strings.Join(from, ", "))
	ret += fmt.Sprintf(" => To: [%s]", strings.Join(to, ", "))
	if len(dports) != 0 {
		ret += fmt.Sprintf(" Ports: [%s]", strings.Join(dports, ", "))
	}
	return ret
}

func (s *SearchContext) CallDepth() string {
	return strconv.Itoa(s.Depth * 2)
}
