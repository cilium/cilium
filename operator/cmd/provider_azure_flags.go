// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_azure

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	FlagsHooks = append(FlagsHooks, &azureFlagsHooks{})
}

type azureFlagsHooks struct{}

func (hook *azureFlagsHooks) RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	flags.String(operatorOption.AzureSubscriptionID, "", "Subscription ID to access Azure API")
	option.BindEnvWithLegacyEnvFallback(vp, operatorOption.AzureSubscriptionID, "AZURE_SUBSCRIPTION_ID")

	flags.String(operatorOption.AzureResourceGroup, "", "Resource group to use for Azure IPAM")
	option.BindEnvWithLegacyEnvFallback(vp, operatorOption.AzureResourceGroup, "AZURE_RESOURCE_GROUP")

	flags.String(operatorOption.AzureUserAssignedIdentityID, "", "ID of the user assigned identity used to auth with the Azure API")
	option.BindEnvWithLegacyEnvFallback(vp, operatorOption.AzureUserAssignedIdentityID, "AZURE_USER_ASSIGNED_IDENTITY_ID")

	flags.Bool(operatorOption.AzureUsePrimaryAddress, false, "Use Azure IP address from interface's primary IPConfigurations")
	option.BindEnvWithLegacyEnvFallback(vp, operatorOption.AzureUsePrimaryAddress, "AZURE_USE_PRIMARY_ADDRESS")

	vp.BindPFlags(flags)
}
