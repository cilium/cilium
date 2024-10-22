// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package pkg

// The following variables are set at compile time via LDFLAGS.
var (
	// Version is the software version.
	Version string
	// GitBranch is the name of the git branch HEAD points to.
	GitBranch string
	// GitHash is the git checksum of the most recent commit in HEAD.
	GitHash string
)
