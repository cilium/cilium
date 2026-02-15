// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/pod-mac-address.yaml
var podMACAddressYAML string

type podMACAddress struct{}

func (t podMACAddress) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pod-mac-address", ct).
		WithResources(podMACAddressYAML).
		WithScenarios(tests.PodMACAddress())
}
