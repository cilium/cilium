// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/pkg/versioncheck"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
)

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
	NetworkProfile    struct {
		NetworkPlugin string `json:"networkPlugin"`
	} `json:"networkProfile"`
}

// For the global auto-detection mechanism to properly work when on AKS, we need
// to determine if the cluster is in BYOCNI mode before determining which
// DatapathMode to use.
func (k *K8sInstaller) azureAutodetect() error {
	if err := k.azureRetrieveSubscriptionID(); err != nil {
		return err
	}

	return k.azureRetrieveAKSClusterInfo()
}

// Retrieve subscription ID to pass to other `az` commands:
// - From user-given subscription name, if provided.
// - From default subscription, if not provided.
//
// Optionally, it might be provided via the `--azure-subscription-id` flag,
// which is currently a hidden feature not advertised to the users and intended
// for development purposes, notably CI usage where `az` CLI is not available.
// If provided, it bypasses auto-detection and `--azure-subscription`.
func (k *K8sInstaller) azureRetrieveSubscriptionID() error {
	if k.params.Azure.SubscriptionID != "" {
		k.Log("ℹ️  Using manually configured Azure subscription ID %s", k.params.Azure.SubscriptionID)
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
// When using Azure IPAM, the CLI will needs to know about this intermediate
// resource group for creating the Service Principal, and thus derives it from
// the user-given resource group and cluster name using `az aks show`.
//
// Optionally, it might be provided via the `--azure-node-resource-group` flag,
// which is currently a hidden feature not advertised to the users and intended
// for development purposes, notably CI usage where `az` CLI is not available.
// If provided, it bypasses the requirement for `--azure-resource-group`.
//
// When using AKS BYOCNI, the CLI does not need any other Azure flags as it does
// not use Azure IPAM. We can detect if the cluster has been created in BYOCNI
// mode by also using `az aks show`.
func (k *K8sInstaller) azureRetrieveAKSClusterInfo() error {
	// If the hidden `--azure-node-resource-group` flag is provided, we assume the
	// user know what they're doing and we are not in BYOCNI mode because this
	// flag is not necessary for BYOCNI, so we skip auto-detection.
	if k.params.Azure.AKSNodeResourceGroup != "" {
		k.Log("ℹ️  Using manually configured Azure AKS node resource group %s", k.params.Azure.AKSNodeResourceGroup)
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

	if clusterInfo.NetworkProfile.NetworkPlugin == "none" {
		// If we are in BYOCNI mode, we won't need any other Azure flags
		k.Log("✅ Detected Azure AKS cluster in BYOCNI mode (no CNI plugin pre-installed)")
		k.params.Azure.IsBYOCNI = true
	} else {
		// If we are not in BYOCNI, we derive AKSNodeResourceGroup from retrieved
		// info so that it can be used later on for creating the Service Principal
		k.Log("✅ Derived Azure AKS node resource group %s from resource group %s", clusterInfo.NodeResourceGroup, k.params.Azure.ResourceGroupName)
		k.params.Azure.AKSNodeResourceGroup = clusterInfo.NodeResourceGroup
	}

	return nil
}

// Use Service Principal provided by user if available, otherwise automatically create a new Service Principal with
// Contributor privileges (required for IPAM within the Cilium Operator) and restrict its scope to the strict minimum
// (i.e. the AKS node resource group in which Cilium will be installed).
//
// We create a new Service Principal for each installation by design:
// - Having dedicated SPs with minimal privileges over their own AKS clusters is more secure.
// - Even if we wanted to re-use pre-existing SPs, it would not be possible:
//   - The ClientSecret (password) of an SP is only displayed at creation time, and cannot be
//     retrieved at a later time.
//   - Specifying a name (--name) when creating a SP creates a new SP on first call, but then
//     overwrites the existing SP with a new ClientSecret on subsequent calls, which potentially
//     interferes with existing installations.
func (k *K8sInstaller) azureSetupServicePrincipal() error {
	// Since we depend on SubscriptionID and AKSNodeResourceGroup being properly
	// set to create the Service Principal, we run the auto-detection mechanism if
	// it was skipped due to the user manually setting `--datapath-mode=azure`.
	if k.params.Azure.SubscriptionID == "" || k.params.Azure.AKSNodeResourceGroup == "" {
		if err := k.azureAutodetect(); err != nil {
			return err
		}
	}

	if k.params.Azure.TenantID == "" && k.params.Azure.ClientID == "" && k.params.Azure.ClientSecret == "" {
		k.Log("🚀 Creating Azure Service Principal for Cilium Azure operator...")
		bytes, err := k.azExec("ad", "sp", "create-for-rbac", "--scopes", "/subscriptions/"+k.params.Azure.SubscriptionID+"/resourceGroups/"+k.params.Azure.AKSNodeResourceGroup, "--role", "Contributor")
		if err != nil {
			return err
		}

		p := azurePrincipalOutput{}
		if err := json.Unmarshal(bytes, &p); err != nil {
			return fmt.Errorf("unable to unmarshal az output: %w", err)
		}

		k.Log("✅ Created Azure Service Principal for Cilium Azure operator with App ID %s and Tenant ID %s", p.AppID, p.Tenant)
		k.Log("ℹ️  Its RBAC privileges are restricted to the AKS node resource group %s", k.params.Azure.AKSNodeResourceGroup)
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

		k.Log("ℹ️  Using manually configured Azure Service Principal for Cilium Azure operator with App ID %s and Tenant ID %s",
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

func (k *K8sInstaller) createAKSSecrets(ctx context.Context) error {
	// Check if secret already exists and reuse it
	_, err := k.client.GetSecret(ctx, k.params.Namespace, defaults.AKSSecretName, metav1.GetOptions{})
	if err == nil {
		k.Log("🔑 Found existing AKS secret %s", defaults.AKSSecretName)
		return nil
	}

	var (
		secretFileName string
	)

	switch {
	case versioncheck.MustCompile(">=1.12.0")(k.chartVersion):
		secretFileName = "templates/cilium-operator/secret.yaml"
	default:
		return fmt.Errorf("cilium version unsupported %s", k.chartVersion)
	}

	secretFile := k.manifests[secretFileName]

	var secret corev1.Secret
	utils.MustUnmarshalYAML([]byte(secretFile), &secret)

	k.Log("🔑 Generated AKS secret %s", defaults.AKSSecretName)
	_, err = k.client.CreateSecret(ctx, k.params.Namespace, &secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create AKS secret %s/%s: %w", k.params.Namespace, defaults.AKSSecretName, err)
	}
	k.pushRollbackStep(func(ctx context.Context) {
		if err := k.client.DeleteSecret(ctx, k.params.Namespace, defaults.AKSSecretName, metav1.DeleteOptions{}); err != nil {
			k.Log("Cannot delete %s Secret: %s", defaults.AKSSecretName, err)
		}
	})

	return nil
}
