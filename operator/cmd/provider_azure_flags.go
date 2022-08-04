// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_azure

package cmd

import (
	operatorOption "github.com/cilium/cilium/operator/option"
)

func init() {
	flags := rootCmd.Flags()

	flags.String(operatorOption.AzureSubscriptionID, "", "Subscription ID to access Azure API")
	regOpts.BindEnvWithLegacyEnvFallback(operatorOption.AzureSubscriptionID, "AZURE_SUBSCRIPTION_ID")

	flags.String(operatorOption.AzureResourceGroup, "", "Resource group to use for Azure IPAM")
	regOpts.BindEnvWithLegacyEnvFallback(operatorOption.AzureResourceGroup, "AZURE_RESOURCE_GROUP")

	flags.String(operatorOption.AzureUserAssignedIdentityID, "", "ID of the user assigned identity used to auth with the Azure API")
	regOpts.BindEnvWithLegacyEnvFallback(operatorOption.AzureUserAssignedIdentityID, "AZURE_USER_ASSIGNED_IDENTITY_ID")

	flags.Bool(operatorOption.AzureUsePrimaryAddress, false, "Use Azure IP address from interface's primary IPConfigurations")
	regOpts.BindEnvWithLegacyEnvFallback(operatorOption.AzureUsePrimaryAddress, "AZURE_USE_PRIMARY_ADDRESS")

	Vp.BindPFlags(flags)
}
