// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"github.com/cilium/cilium/test/helpers"
)

var (
	deploymentManager = helpers.NewDeploymentManager()

	IPSecSecret = helpers.Manifest{
		Filename: "ipsec_secret.yaml",
	}
)
