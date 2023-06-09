// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controlplane_test

import (
	"testing"

	_ "github.com/cilium/cilium/test/controlplane/ciliumnetworkpolicies"
	_ "github.com/cilium/cilium/test/controlplane/node"
	_ "github.com/cilium/cilium/test/controlplane/node/ciliumnodes"
	_ "github.com/cilium/cilium/test/controlplane/services/dualstack"
	_ "github.com/cilium/cilium/test/controlplane/services/graceful-termination"
	_ "github.com/cilium/cilium/test/controlplane/services/nodeport"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func TestControlPlane(t *testing.T) {
	suite.RunSuite(t)
}
