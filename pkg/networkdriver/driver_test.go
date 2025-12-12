// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"path/filepath"
	"testing"

	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/sriov"
)

func TestDriverStoreAndReload(t *testing.T) {
	allocations := map[kube_types.UID]map[kube_types.UID][]allocation{
		kube_types.UID("6bd2a7f7-baf8-4358-a88e-2975f600f0dc"): {
			kube_types.UID("bcf84ccd-99b9-4bad-9f57-2b607f822b3e"): {
				allocation{
					Device: &sriov.PciDevice{
						Addr:            "test-addr-1",
						Driver:          "test-driver-1",
						Vendor:          "test-vendor-1",
						DeviceID:        "test-device-id-1",
						PfName:          "phys-name-1",
						VfID:            1,
						KernelIfaceName: "test-name-1",
					},
				},
				allocation{
					Device: &sriov.PciDevice{
						Addr:            "test-addr-2",
						Driver:          "test-driver-2",
						Vendor:          "test-vendor-2",
						DeviceID:        "test-device-id-2",
						PfName:          "phys-name-2",
						VfID:            2,
						KernelIfaceName: "test-name-2",
					},
				},
			},
			kube_types.UID("f2b841c6-14c5-46f7-856d-ff563f113352"): {
				allocation{
					Device: &dummy.DummyDevice{
						Name:   "test-name-3",
						HWAddr: "test-hw-addr-3",
						MTU:    1500,
						Flags:  "up|running",
					},
				},
			},
		},
		kube_types.UID("7ee48615-8bb3-4f09-acac-fa13e84edaca"): {
			kube_types.UID("e139427b-b920-4a85-8713-b6e549f32051"): {
				allocation{
					Device: &dummy.DummyDevice{
						Name:   "test-name-4",
						HWAddr: "test-hw-addr-4",
						MTU:    1250,
						Flags:  "up|running",
					},
				},
			},
		},
	}

	driver := Driver{
		filePath:    filepath.Join(t.TempDir(), defaultDriverStoreFileName),
		allocations: allocations,
	}
	assert.NoError(t, driver.storeState())

	driver.allocations = nil
	assert.NoError(t, driver.reloadState())

	assert.Equal(t, allocations, driver.allocations)
}
