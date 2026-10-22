// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/cilium/hive/hivetest"

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

func (h *hookedAPI) setHook(hook func()) {
	h.afterListAllNetworkInterfaces = hook
}

func TestFullResync(t *testing.T) {
	t.Run("InstanceDelete", func(t *testing.T) {
		t.Parallel()
		api := apimock.NewAPI(subnets)
		hooked := &hookedAPI{AzureAPI: api}
		mngr := NewInstancesManager(hivetest.Logger(t), hooked, false)
		iteration1(t, api, mngr)
		resynctest.InstanceDelete(t, mngr, hooked.setHook, "i-1")
	})
}
