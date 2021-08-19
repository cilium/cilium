// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build ipam_provider_alibabacloud
// +build ipam_provider_alibabacloud

package main

import (
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/viper"
)

func init() {
	flags := rootCmd.Flags()

	flags.String(operatorOption.AlibabaCloudVPCID, "", "Specific VPC ID for AlibabaCloud ENI. If not set use same VPC as operator")
	option.BindEnv(operatorOption.AlibabaCloudVPCID)

	viper.BindPFlags(flags)
}
