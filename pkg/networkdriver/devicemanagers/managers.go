// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemanagers

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/networkdriver/sriov"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

var (
	errUnknownManagerType             = errors.New("unknown manager type")
	errInvalidConfigurationForManager = errors.New("invalid configuration type for manager")
)

func InitManager(logger *slog.Logger, managerType types.DeviceManagerType, driverCfg any) (types.DeviceManager, error) {
	switch c := driverCfg.(type) {
	case sriov.SRIOVConfig:
		if managerType != types.DeviceManagerTypeSRIOV {
			return nil, fmt.Errorf("%w: expected %T, got %T", errInvalidConfigurationForManager, sriov.SRIOVConfig{}, c)
		}

		return sriov.NewManager(logger, c)

	}

	return nil, errUnknownManagerType
}
