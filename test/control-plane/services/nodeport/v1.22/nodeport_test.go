// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1_22

import (
	"testing"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/control-plane/services"
)

func TestNodePort(t *testing.T) {
	modConfig := func(c *option.DaemonConfig) { c.EnableNodePort = true }
	services.NewGoldenServicesTest(t, "nodeport-control-plane").Run(t, "1.22", modConfig)
}
