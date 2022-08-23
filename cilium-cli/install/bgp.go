// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

func (k *K8sInstaller) bgpEnabled() bool {
	return k.params.configOverwrites["bgp-announce-lb-ip"] == "true"
}
