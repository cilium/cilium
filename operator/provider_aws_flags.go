// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_aws

package main

import (
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	flags := rootCmd.Flags()

	flags.Var(option.NewNamedMapOptions(operatorOption.AWSInstanceLimitMapping, &operatorOption.Config.AWSInstanceLimitMapping, nil),
		operatorOption.AWSInstanceLimitMapping,
		`Add or overwrite mappings of AWS instance limit in the form of `+
			`{"AWS instance type": "Maximum Network Interfaces","IPv4 Addresses `+
			`per Interface","IPv6 Addresses per Interface"}. cli example: `+
			`--aws-instance-limit-mapping=a1.medium=2,4,4 `+
			`--aws-instance-limit-mapping=a2.somecustomflavor=4,5,6 `+
			`configmap example: {"a1.medium": "2,4,4", "a2.somecustomflavor": "4,5,6"}`)
	option.BindEnv(operatorOption.AWSInstanceLimitMapping)

	flags.Bool(operatorOption.AWSReleaseExcessIPs, false, "Enable releasing excess free IP addresses from AWS ENI.")
	option.BindEnv(operatorOption.AWSReleaseExcessIPs)

	flags.Int(operatorOption.ExcessIPReleaseDelay, 180, "Number of seconds operator would wait before it releases an IP previously marked as excess")
	option.BindEnv(operatorOption.ExcessIPReleaseDelay)

	flags.Var(option.NewNamedMapOptions(operatorOption.ENITags, &operatorOption.Config.ENITags, nil),
		operatorOption.ENITags, "ENI tags in the form of k1=v1 (multiple k/v pairs can be passed by repeating the CLI flag)")
	option.BindEnv(operatorOption.ENITags)

	flags.Bool(operatorOption.UpdateEC2AdapterLimitViaAPI, false, "Use the EC2 API to update the instance type to adapter limits")
	option.BindEnv(operatorOption.UpdateEC2AdapterLimitViaAPI)

	flags.String(operatorOption.EC2APIEndpoint, "", "AWS API endpoint for the EC2 service")
	option.BindEnv(operatorOption.EC2APIEndpoint)

	viper.BindPFlags(flags)
}
