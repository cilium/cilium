// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shell

const (
	// endMarker marks the end of output from a command.
	endMarker = "<<end>>"

	// errorMarker marks the command as failed. If the command
	// fails this acts as the end of output mark.
	errorMarker = "<<error>>"

	// stdoutMarker marks the output to be from the stdout buffer.
	stdoutMarker = "[stdout]"

	// stderrMarker marks the output to be from the stderr buffer.
	stderrMarker = "[stderr]"
)
