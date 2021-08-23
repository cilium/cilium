// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package install

func (k *K8sInstaller) bgpEnabled() bool {
	return k.params.configOverwrites["bgp-announce-lb-ip"] == "true"
}
