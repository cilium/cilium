// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package flowdebug

var perFlowDebug = false

// Enable enables per-flow debugging
func Enable() {
	perFlowDebug = true
}

// Enabled reports the status of per-flow debugging
func Enabled() bool {
	return perFlowDebug
}
