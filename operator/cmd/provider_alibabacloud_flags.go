// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_alibabacloud

package cmd

import (
	operatorOption "github.com/cilium/cilium/operator/option"
)

func init() {
	flags := rootCmd.Flags()

	flags.String(operatorOption.AlibabaCloudVPCID, "", "Specific VPC ID for AlibabaCloud ENI. If not set use same VPC as operator")
	regOpts.BindEnv(operatorOption.AlibabaCloudVPCID)

	Vp.BindPFlags(flags)
}
