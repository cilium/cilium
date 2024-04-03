// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"io"
	stdlog "log"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

type Tracing int

const (
	TRACE_DISABLED Tracing = iota
	TRACE_ENABLED
	TRACE_VERBOSE
)

// TraceEnabled returns true if the SearchContext requests tracing.
func (s *SearchContext) TraceEnabled() bool {
	return s.Trace != TRACE_DISABLED
}

// PolicyTrace logs the given message into the SearchContext logger only if
// TRACE_ENABLED or TRACE_VERBOSE is enabled in the receiver's SearchContext.
func (s *SearchContext) PolicyTrace(format string, a ...interface{}) {
	if s.TraceEnabled() {
		log.Debugf(format, a...)
		if s.Logging != nil {
			format = "%-" + s.CallDepth() + "s" + format
			a = append([]interface{}{""}, a...)
			s.Logging.Printf(format, a...)
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
			s.Logging.Printf(format, a...)
		}
	}
}

// SearchContext defines the context while evaluating policy
type SearchContext struct {
	Trace   Tracing
	Depth   int
	Logging *stdlog.Logger
	From    labels.LabelArray
	To      labels.LabelArray
	DPorts  []*models.Port
	// rulesSelect specifies whether or not to check whether a rule which is
	// being analyzed using this SearchContext matches either From or To.
	// This is used to avoid using EndpointSelector.Matches() if possible,
	// since it is costly in terms of performance.
	rulesSelect bool
}

func (s *SearchContext) String() string {
	from := make([]string, 0, len(s.From))
	to := make([]string, 0, len(s.To))
	dports := make([]string, 0, len(s.DPorts))
	for _, fromLabel := range s.From {
		from = append(from, fromLabel.String())
	}
	for _, toLabel := range s.To {
		to = append(to, toLabel.String())
	}
	// We should avoid to use `fmt.Sprintf()` since
	// it is well-known for not being opimal in terms of
	// CPU and memory allocations.
	// See https://github.com/cilium/cilium/issues/19571
	for _, dport := range s.DPorts {
		dportStr := dport.Name
		if dportStr == "" {
			dportStr = strconv.FormatUint(uint64(dport.Port), 10)
		}
		dports = append(dports, dportStr+"/"+dport.Protocol)
	}
	fromStr := strings.Join(from, ", ")
	toStr := strings.Join(to, ", ")
	if len(dports) != 0 {
		dportStr := strings.Join(dports, ", ")
		return "From: [" + fromStr + "] => To: [" + toStr + "] Ports: [" + dportStr + "]"
	}
	return "From: [" + fromStr + "] => To: [" + toStr + "]"
}

func (s *SearchContext) CallDepth() string {
	return strconv.Itoa(s.Depth * 2)
}

// WithLogger returns a shallow copy of the received SearchContext with the
// logging set to write to 'log'.
func (s *SearchContext) WithLogger(log io.Writer) *SearchContext {
	result := *s
	result.Logging = stdlog.New(log, "", 0)
	if result.Trace == TRACE_DISABLED {
		result.Trace = TRACE_ENABLED
	}
	return &result
}
