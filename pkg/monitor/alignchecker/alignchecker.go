// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alignchecker

import (
	"reflect"

	check "github.com/cilium/cilium/pkg/alignchecker"
	"github.com/cilium/cilium/pkg/monitor"
)

// See pkg/datapath/alignchecker/alignchecker.go:CheckStructAlignments()
// comment.
func CheckStructAlignments(path string) error {
	// Validate alignments of C and Go equivalent structs
	toCheck := map[string][]reflect.Type{
		"trace_notify":          {reflect.TypeOf(monitor.TraceNotify{})},
		"drop_notify":           {reflect.TypeOf(monitor.DropNotify{})},
		"debug_msg":             {reflect.TypeOf(monitor.DebugMsg{})},
		"debug_capture_msg":     {reflect.TypeOf(monitor.DebugCapture{})},
		"policy_verdict_notify": {reflect.TypeOf(monitor.PolicyVerdictNotify{})},
		"trace_sock_notify":     {reflect.TypeOf(monitor.TraceSockNotify{})},
	}
	return check.CheckStructAlignments(path, toCheck, true)
}
