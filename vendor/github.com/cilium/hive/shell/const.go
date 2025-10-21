// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shell

const (
	// endMarker marks the end of output from a command.
	endMarker = "<<end>>"

	// stdoutMarker marks the output to be from the stdout buffer.
	stdoutMarker = "[stdout]"

	// stderrMarker marks the output to be from the stderr buffer.
	stderrMarker = "[stderr]"
)
