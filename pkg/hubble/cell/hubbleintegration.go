// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import "github.com/cilium/cilium/pkg/option"

// Hubble is responsible for configuration, initialization, and shutdown of
// every Hubble components including the Hubble observer servers (TCP, UNIX
// domain socket), the Hubble metrics server, etc.
type Hubble struct {
	agentConfig *option.DaemonConfig
}

// new creates and return a new Hubble.
func new(
	agentConfig *option.DaemonConfig,
) *Hubble {
	return &Hubble{
		agentConfig: agentConfig,
	}
}
