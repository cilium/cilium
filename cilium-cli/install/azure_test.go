// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/cli/values"
)

func TestK8sInstaller_setAzureResourceGroupFromHelmValue(t *testing.T) {
	nameFromFlag := "name-from-flag"
	nameFromHelmValue := "name-from-helm-value"

	// Test the case where --azure-resource-group flag is set.
	installer := &K8sInstaller{
		params: Parameters{
			Azure: AzureParameters{ResourceGroupName: nameFromFlag},
		},
	}
	err := installer.setAzureResourceGroupFromHelmValue()
	assert.NoError(t, err)
	assert.Equal(t, nameFromFlag, installer.params.Azure.ResourceGroupName)

	// Test the case where azure.resourceGroup Helm value is set.
	installer = &K8sInstaller{
		params: Parameters{
			HelmOpts: values.Options{
				Values: []string{fmt.Sprintf("azure.resourceGroup=%s", nameFromHelmValue)},
			},
		},
	}
	err = installer.setAzureResourceGroupFromHelmValue()
	assert.NoError(t, err)
	assert.Equal(t, nameFromHelmValue, installer.params.Azure.ResourceGroupName)
}
