// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_openstack

package cmd

import (
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	flags := rootCmd.Flags()

	flags.String(operatorOption.OpenStackNetworkID, "", "Specific Network ID for OpenStack. If not set use same VPC as operator")
	option.BindEnv(Vp, operatorOption.OpenStackNetworkID)
	flags.String(operatorOption.OpenStackSubnetID, "", "Specific subnet ID for OpenStack.")
	option.BindEnv(Vp, operatorOption.OpenStackSubnetID)
	flags.String(operatorOption.OpenStackProjectID, "", "Specific project ID for OpenStack.")
	option.BindEnv(Vp, operatorOption.OpenStackProjectID)

	Vp.BindPFlags(flags)
}
