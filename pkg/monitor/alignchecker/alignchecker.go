// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alignchecker

import (
	check "github.com/cilium/cilium/pkg/alignchecker"
	"github.com/cilium/cilium/pkg/monitor"
)

// See pkg/datapath/alignchecker/alignchecker.go:CheckStructAlignments()
// comment.
func CheckStructAlignments(path string) error {
	// Validate alignments of C and Go equivalent structs
	toCheck := map[string][]any{
		"trace_notify":          {monitor.TraceNotify{}},
		"drop_notify":           {monitor.DropNotify{}},
		"debug_msg":             {monitor.DebugMsg{}},
		"debug_capture_msg":     {monitor.DebugCapture{}},
		"policy_verdict_notify": {monitor.PolicyVerdictNotify{}},
		"trace_sock_notify":     {monitor.TraceSockNotify{}},
	}
	return check.CheckStructAlignments(path, toCheck, true)
}
