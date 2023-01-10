// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_azure

package cmd

import (
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	flags := rootCmd.Flags()

	flags.String(operatorOption.AzureSubscriptionID, "", "Subscription ID to access Azure API")
	option.BindEnvWithLegacyEnvFallback(Vp, operatorOption.AzureSubscriptionID, "AZURE_SUBSCRIPTION_ID")

	flags.String(operatorOption.AzureResourceGroup, "", "Resource group to use for Azure IPAM")
	option.BindEnvWithLegacyEnvFallback(Vp, operatorOption.AzureResourceGroup, "AZURE_RESOURCE_GROUP")

	flags.String(operatorOption.AzureUserAssignedIdentityID, "", "ID of the user assigned identity used to auth with the Azure API")
	option.BindEnvWithLegacyEnvFallback(Vp, operatorOption.AzureUserAssignedIdentityID, "AZURE_USER_ASSIGNED_IDENTITY_ID")

	flags.Bool(operatorOption.AzureUsePrimaryAddress, false, "Use Azure IP address from interface's primary IPConfigurations")
	option.BindEnvWithLegacyEnvFallback(Vp, operatorOption.AzureUsePrimaryAddress, "AZURE_USE_PRIMARY_ADDRESS")

	Vp.BindPFlags(flags)
}
