/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azure

import (
	"bytes"
	"testing"

	"github.com/Azure/azure-sdk-for-go/arm/containerregistry"
	"github.com/Azure/go-autorest/autorest/to"
)

type fakeClient struct {
	results containerregistry.RegistryListResult
}

func (f *fakeClient) List() (containerregistry.RegistryListResult, error) {
	return f.results, nil
}

func Test(t *testing.T) {
	configStr := `
    {
        "aadClientId": "foo",
        "aadClientSecret": "bar"
    }`
	result := containerregistry.RegistryListResult{
		Value: &[]containerregistry.Registry{
			{
				Name: to.StringPtr("foo"),
				RegistryProperties: &containerregistry.RegistryProperties{
					LoginServer: to.StringPtr("foo-microsoft.azurecr.io"),
				},
			},
			{
				Name: to.StringPtr("bar"),
				RegistryProperties: &containerregistry.RegistryProperties{
					LoginServer: to.StringPtr("bar-microsoft.azurecr.io"),
				},
			},
			{
				Name: to.StringPtr("baz"),
				RegistryProperties: &containerregistry.RegistryProperties{
					LoginServer: to.StringPtr("baz-microsoft.azurecr.io"),
				},
			},
		},
	}
	fakeClient := &fakeClient{
		results: result,
	}

	provider := &acrProvider{
		registryClient: fakeClient,
	}
	provider.loadConfig(bytes.NewBufferString(configStr))

	creds := provider.Provide()

	if len(creds) != len(*result.Value) {
		t.Errorf("Unexpected list: %v, expected length %d", creds, len(*result.Value))
	}
	for _, cred := range creds {
		if cred.Username != "foo" {
			t.Errorf("expected 'foo' for username, saw: %v", cred.Username)
		}
		if cred.Password != "bar" {
			t.Errorf("expected 'bar' for password, saw: %v", cred.Username)
		}
	}
	for _, val := range *result.Value {
		registryName := getLoginServer(val)
		if _, found := creds[registryName]; !found {
			t.Errorf("Missing expected registry: %s", registryName)
		}
	}
}
