// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package install

import (
	"context"
	"encoding/json"
	"fmt"
)

type azureVersionValidation struct{}

func (m *azureVersionValidation) Name() string {
	return "az-binary"
}

func (m *azureVersionValidation) Check(ctx context.Context, k *K8sInstaller) error {
	_, err := k.azExec("version")
	if err != nil {
		return err
	}

	k.Log("✅ Detected az binary")

	return nil
}

type accountInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type azurePrincipalOutput struct {
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`
	Name        string `json:"name"`
	Password    string `json:"password"`
	Tenant      string `json:"tenant"`
}

type aksClusterInfo struct {
	NodeResourceGroup string `json:"nodeResourceGroup"`
}

func (k *K8sInstaller) aksSetup(ctx context.Context) error {
	if err := k.azureRetrieveSubscriptionID(ctx); err != nil {
		return err
	}

	if err := k.azureRetrieveAKSNodeResourceGroup(ctx); err != nil {
		return err
	}

	return k.azureSetupServicePrincipal(ctx)
}

// Retrieve subscription ID to pass to other `az` commands:
// - From user-given subscription name, if provided.
// - From default subscription, if not provided.
//
// Optionally, it might be provided via the `--azure-subscription-id` flag,
// which is currently a hidden feature not advertised to the users and intended
// for development purposes, notably CI usage where `az` CLI is not available.
// If provided, it bypasses auto-detection and `--azure-subscription`.
func (k *K8sInstaller) azureRetrieveSubscriptionID(ctx context.Context) error {
	if k.params.Azure.SubscriptionID != "" {
		k.Log("ℹ️ Using manually configured Azure subscription ID %s", k.params.Azure.SubscriptionID)
		return nil
	}

	args := []string{"account", "show"}
	if k.params.Azure.SubscriptionName != "" {
		args = append(args, "--subscription", k.params.Azure.SubscriptionName)
	}
	bytes, err := k.azExec(args...)
	if err != nil {
		return err
	}

	ai := accountInfo{}
	if err := json.Unmarshal(bytes, &ai); err != nil {
		return fmt.Errorf("unable to unmarshal az output: %w", err)
	}

	k.Log("✅ Derived Azure subscription ID %s from subscription %s", ai.ID, ai.Name)
	k.params.Azure.SubscriptionID = ai.ID

	return nil
}

// `az aks create` requires an existing resource group in which to create a
// new AKS cluster, but a single resource group may hold multiple AKS clusters.
//
// Internally, AKS creates an intermediate resource group (named
// `MC_{RG_name}_{cluster_name}_{location}`) to regroup all AKS nodes for
// this cluster. See Azure documentation for more details:
// https://docs.microsoft.com/en-us/azure/aks/faq#why-are-two-resource-groups-created-with-aks
//
// The CLI installs itself into this intermediate resource group, and thus
// derives it from the user-given resource group and cluster name using
// `az aks show`.
//
// Optionally, it might be provided via the `--azure-node-resource-group` flag,
// which is currently a hidden feature not advertised to the users and intended
// for development purposes, notably CI usage where `az` CLI is not available.
// If provided, it bypasses the requirement for `--azure-resource-group`.
func (k *K8sInstaller) azureRetrieveAKSNodeResourceGroup(ctx context.Context) error {
	if k.params.Azure.AKSNodeResourceGroup != "" {
		k.Log("ℹ️ Using manually configured Azure AKS node resource group %s", k.params.Azure.AKSNodeResourceGroup)
		return nil
	}

	if k.params.Azure.ResourceGroupName == "" {
		k.Log("❌ Azure resource group is required, please specify --azure-resource-group")
		return fmt.Errorf("missing Azure resource group name")
	}

	bytes, err := k.azExec("aks", "show", "--subscription", k.params.Azure.SubscriptionID, "--resource-group", k.params.Azure.ResourceGroupName, "--name", k.params.ClusterName)
	if err != nil {
		return err
	}

	clusterInfo := aksClusterInfo{}
	if err := json.Unmarshal(bytes, &clusterInfo); err != nil {
		return fmt.Errorf("unable to unmarshal az output: %w", err)
	}

	k.Log("✅ Derived Azure AKS node resource group %s from resource group %s", clusterInfo.NodeResourceGroup, k.params.Azure.ResourceGroupName)
	k.params.Azure.AKSNodeResourceGroup = clusterInfo.NodeResourceGroup

	return nil
}

// Use Service Principal provided by user if available, otherwise automatically create a new Service Principal with
// Contributor privileges (required for IPAM within the Cilium Operator) and restrict its scope to the strict minimum
// (i.e. the AKS node resource group in which Cilium will be installed).
//
// We create a new Service Principal for each installation by design:
// - Having dedicated SPs with minimal privileges over their own AKS clusters is more secure.
// - Even if we wanted to re-use pre-existing SPs, it would not be possible:
// 	- The ClientSecret (password) of an SP is only displayed at creation time, and cannot be
// 		retrieved at a later time.
// 	- Specifying a name (--name) when creating a SP creates a new SP on first call, but then
// 		overwrites the existing SP with a new ClientSecret on subsequent calls, which potentially
// 		interferes with existing installations.
func (k *K8sInstaller) azureSetupServicePrincipal(ctx context.Context) error {
	if k.params.Azure.TenantID == "" && k.params.Azure.ClientID == "" && k.params.Azure.ClientSecret == "" {
		k.Log("🚀 Creating Azure Service Principal for Cilium operator...")
		bytes, err := k.azExec("ad", "sp", "create-for-rbac", "--scopes", "/subscriptions/"+k.params.Azure.SubscriptionID+"/resourceGroups/"+k.params.Azure.AKSNodeResourceGroup, "--role", "Contributor")
		if err != nil {
			return err
		}

		p := azurePrincipalOutput{}
		if err := json.Unmarshal(bytes, &p); err != nil {
			return fmt.Errorf("unable to unmarshal az output: %w", err)
		}

		k.Log("✅ Created Azure Service Principal for Cilium operator with App ID %s and Tenant ID %s", p.AppID, p.Tenant)
		k.Log("ℹ️ Its RBAC privileges are restricted to the AKS node resource group %s", k.params.Azure.AKSNodeResourceGroup)
		k.params.Azure.TenantID = p.Tenant
		k.params.Azure.ClientID = p.AppID
		k.params.Azure.ClientSecret = p.Password
	} else {
		if k.params.Azure.TenantID == "" || k.params.Azure.ClientID == "" || k.params.Azure.ClientSecret == "" {
			k.Log(`❌ All three parameters are required for using an existing Azure Service Principal:
   - Tenant ID (--azure-tenant-id)
   - Client ID (--azure-client-id)
   - Client Secret (--azure-client-secret)`)
			return fmt.Errorf("missing at least one of Azure Service Principal parameters")
		}

		k.Log("ℹ️ Using manually configured Azure Service Principal for Cilium operator with App ID %s and Tenant ID %s",
			k.params.Azure.ClientID, k.params.Azure.TenantID)
	}

	return nil
}

// Wrapper function forcing `az` output to be in JSON for unmarshalling purposes
// and suppressing warnings from preview, deprecated and experimental commands.
func (k *K8sInstaller) azExec(args ...string) ([]byte, error) {
	args = append(args, "--output", "json", "--only-show-errors")
	return k.Exec("az", args...)
}
