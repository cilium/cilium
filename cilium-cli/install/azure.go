// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

type azureVersionValidation struct{}

func (m *azureVersionValidation) Name() string {
	return "az-binary"
}

func (m *azureVersionValidation) Check(ctx context.Context, k *K8sInstaller) error {
	cmd := azCommand("version")
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to execute \"az version\": %w", err)
	}

	k.Log("✅ Detected az binary")

	return nil
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

type accountInfo struct {
	ID string `json:"id"`
}

func (k *K8sInstaller) createAzureServicePrincipal(ctx context.Context) error {
	if k.params.Azure.TenantID == "" && k.params.Azure.ClientID == "" && k.params.Azure.ClientSecret == "" {
		k.Log("🚀 Creating service principal for Cilium operator...")
		args := []string{"ad", "sp", "create-for-rbac"}
		cmd := azCommand(args...)
		bytes, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("unable to execute \"az %s\": %w", args, err)
		}

		p := azurePrincipalOutput{}
		if err := json.Unmarshal(bytes, &p); err != nil {
			return fmt.Errorf("unable to unmarshal az output: %w", err)
		}

		k.Log("✅ Created service principal for cilium operator with App ID %s and tenant ID %s", p.AppID, p.Tenant)
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

		k.Log("✅ Using manually configured principal for cilium operator with App ID %s and tenant ID %s",
			k.params.Azure.ClientID, k.params.Azure.TenantID)
	}

	args := []string{"account", "show"}
	cmd := azCommand(args...)
	bytes, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to execute \"az %s\": %w", args, err)
	}

	ai := accountInfo{}
	if err := json.Unmarshal(bytes, &ai); err != nil {
		return fmt.Errorf("unable to unmarshal az output: %w", err)
	}

	k.Log("✅ Derived Azure subscription id %s", ai.ID)
	k.params.Azure.DerivedSubscriptionID = ai.ID

	args = []string{"aks", "show", "--resource-group", k.params.Azure.ResourceGroupName, "--name", k.params.ClusterName}
	if k.params.Azure.SubscriptionID != "" {
		args = append(args, "--subscription", k.params.Azure.SubscriptionID)
	}
	cmd = azCommand(args...)
	bytes, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to execute \"az %s\": %w", args, err)
	}

	clusterInfo := aksClusterInfo{}
	if err := json.Unmarshal(bytes, &clusterInfo); err != nil {
		return fmt.Errorf("unable to unmarshal az output: %w", err)
	}

	k.Log("✅ Derived Azure node resource group %s", clusterInfo.NodeResourceGroup)
	k.params.Azure.ResourceGroup = clusterInfo.NodeResourceGroup

	return nil
}

// azCommand is a wrapper function around running the "az" binary. It forces
// all output to be in JSON.
func azCommand(args ...string) *exec.Cmd {
	all := append([]string{}, args...)
	all = append(all, "--output", "json")
	return exec.Command("az", all...)
}
