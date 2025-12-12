// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemanagers

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/sriov"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

func InitManagers(logger *slog.Logger, managerConfigs *v2alpha1.CiliumNetworkDriverDeviceManagerConfig) (map[types.DeviceManagerType]types.DeviceManager, error) {
	result := make(map[types.DeviceManagerType]types.DeviceManager)

	if managerConfigs.SRIOV != nil && managerConfigs.SRIOV.Enabled {
		sriovMgr, err := sriov.NewManager(logger, managerConfigs.SRIOV)
		if err != nil {
			return nil, err
		}

		result[types.DeviceManagerTypeSRIOV] = sriovMgr
	}

	if managerConfigs.Dummy != nil && managerConfigs.Dummy.Enabled {
		dummyMgr, err := dummy.NewManager(logger, managerConfigs.Dummy)
		if err != nil {
			return nil, err
		}

		result[types.DeviceManagerTypeSRIOV] = dummyMgr
	}

	return result, nil
}
