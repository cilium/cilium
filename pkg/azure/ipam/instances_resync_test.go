// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/ipam/resynctest"
)

// hookedAPI calls afterListAllNetworkInterfaces while a full resync holds its Azure snapshot.
type hookedAPI struct {
	AzureAPI
	afterListAllNetworkInterfaces func()
}

func (h *hookedAPI) ListAllNetworkInterfaces(ctx context.Context) ([]*armnetwork.Interface, error) {
	interfaces, err := h.AzureAPI.ListAllNetworkInterfaces(ctx)
	if h.afterListAllNetworkInterfaces != nil {
		h.afterListAllNetworkInterfaces()
	}
	return interfaces, err
}

// TestFullResyncKeepsConcurrentInstanceDelete deletes an instance inside a full resync's fetch window.
func TestFullResyncKeepsConcurrentInstanceDelete(t *testing.T) {
	const instanceID = "i-1"

	api := apimock.NewAPI(subnets)
	hooked := &hookedAPI{AzureAPI: api}
	mngr := NewInstancesManager(hivetest.Logger(t), hooked, false)
	iteration1(t, api, mngr)
	require.True(t, mngr.HasInstance(instanceID))

	resynctest.RunDuringFullResync(t,
		func(hook func()) { hooked.afterListAllNetworkInterfaces = hook },
		func(ctx context.Context) error {
			_, err := mngr.Resync(ctx)
			return err
		},
		func() error { return nil },
		func() {
			mngr.DeleteInstance(instanceID)
		})

	require.False(t, mngr.HasInstance(instanceID))
}
