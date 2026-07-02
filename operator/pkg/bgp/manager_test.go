// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestVersionMigration(t *testing.T) {
	tests := []struct {
		name                   string
		crd                    *v1.CustomResourceDefinition
		expectedReturnValue    bool
		expectedStoredVersions []string
	}{
		{
			name: "Migrate v2alpha1",
			crd: &v1.CustomResourceDefinition{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "ciliumbgppeerconfigs.cilium.io",
				},
				Status: v1.CustomResourceDefinitionStatus{
					StoredVersions: []string{"v2", "v2alpha1"},
				},
			},
			expectedReturnValue:    true,
			expectedStoredVersions: []string{"v2"},
		},
		{
			name: "No Migration",
			crd: &v1.CustomResourceDefinition{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "ciliumbgppeerconfigs.cilium.io",
				},
				Status: v1.CustomResourceDefinitionStatus{
					StoredVersions: []string{"v2"},
				},
			},
			expectedReturnValue:    false,
			expectedStoredVersions: []string{"v2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), TestTimeout*3)
			t.Cleanup(func() {
				cancel()
			})

			fakeClientSet, _ := k8sClient.NewFakeClientset(slog.Default())
			crdClient := fakeClientSet.ApiextensionsV1().CustomResourceDefinitions()
			client := resourceClient[*v2.CiliumBGPPeerConfig]{
				lister:  list,
				patcher: fakeClientSet.CiliumV2().CiliumBGPPeerConfigs().Patch,
			}
			versionFromMigrate := "v2alpha1"
			_, err := crdClient.Create(
				ctx, tt.crd, meta_v1.CreateOptions{},
			)
			require.NoError(t, err)

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				migrated, err := storageVersionMigrator(
					ctx, crdClient, tt.crd.Name, client, versionFromMigrate,
				)
				if !assert.NoError(ct, err, "Failed to migrate storage version") {
					return
				}

				crd, err := crdClient.Get(ctx, tt.crd.Name, meta_v1.GetOptions{})
				if !assert.NoError(ct, err, "Failed to get CustomResourceDefinition") {
					return
				}
				assert.Equal(ct, tt.expectedStoredVersions, crd.Status.StoredVersions, "Unexpected Status.StoredVersions")
				assert.Equal(ct, tt.expectedReturnValue, migrated, "Unexpected return value")
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func list() []*v2.CiliumBGPPeerConfig {
	return nil
}
