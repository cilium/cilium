// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_aws

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	FlagsHooks = append(FlagsHooks, &awsFlagsHooks{})
}

type awsFlagsHooks struct{}

func (hook *awsFlagsHooks) RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	flags.Var(option.NewNamedMapOptions(operatorOption.AWSInstanceLimitMapping, &operatorOption.Config.AWSInstanceLimitMapping, nil),
		operatorOption.AWSInstanceLimitMapping,
		`Add or overwrite mappings of AWS instance limit in the form of `+
			`{"AWS instance type": "Maximum Network Interfaces","IPv4 Addresses `+
			`per Interface","IPv6 Addresses per Interface"}. cli example: `+
			`--aws-instance-limit-mapping=a1.medium=2,4,4 `+
			`--aws-instance-limit-mapping=a2.somecustomflavor=4,5,6 `+
			`configmap example: {"a1.medium": "2,4,4", "a2.somecustomflavor": "4,5,6"}`)
	option.BindEnv(vp, operatorOption.AWSInstanceLimitMapping)

	flags.Bool(operatorOption.AWSReleaseExcessIPs, false, "Enable releasing excess free IP addresses from AWS ENI.")
	option.BindEnv(vp, operatorOption.AWSReleaseExcessIPs)

	flags.Int(operatorOption.ExcessIPReleaseDelay, 180, "Number of seconds operator would wait before it releases an IP previously marked as excess")
	option.BindEnv(vp, operatorOption.ExcessIPReleaseDelay)

	flags.Bool(operatorOption.AWSEnablePrefixDelegation, false, "Allows operator to allocate prefixes to ENIs instead of individual IP addresses")
	option.BindEnv(vp, operatorOption.AWSEnablePrefixDelegation)

	flags.Var(option.NewNamedMapOptions(operatorOption.ENITags, &operatorOption.Config.ENITags, nil),
		operatorOption.ENITags, "ENI tags in the form of k1=v1 (multiple k/v pairs can be passed by repeating the CLI flag)")
	option.BindEnv(vp, operatorOption.ENITags)

	flags.Var(option.NewNamedMapOptions(operatorOption.ENIGarbageCollectionTags, &operatorOption.Config.ENIGarbageCollectionTags, nil),
		operatorOption.ENIGarbageCollectionTags, "Additional tags attached to ENIs created by Cilium. Dangling ENIs with this tag will be garbage collected")
	option.BindEnv(vp, operatorOption.ENIGarbageCollectionTags)

	flags.Duration(operatorOption.ENIGarbageCollectionInterval, defaults.ENIGarbageCollectionInterval,
		"Interval for garbage collection of unattached ENIs. Set to 0 to disable")
	option.BindEnv(vp, operatorOption.ENIGarbageCollectionInterval)

	flags.Bool(operatorOption.UpdateEC2AdapterLimitViaAPI, true, "Use the EC2 API to update the instance type to adapter limits")
	option.BindEnv(vp, operatorOption.UpdateEC2AdapterLimitViaAPI)

	flags.Bool(operatorOption.AWSUsePrimaryAddress, false, "Allows for using primary address of the ENI for allocations on the node")
	option.BindEnv(vp, operatorOption.AWSUsePrimaryAddress)

	flags.String(operatorOption.EC2APIEndpoint, "", "AWS API endpoint for the EC2 service")
	option.BindEnv(vp, operatorOption.EC2APIEndpoint)

	vp.BindPFlags(flags)
}
