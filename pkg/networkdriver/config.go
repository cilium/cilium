// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// validateFilters ensures that we do not have more than one filter matching the same device.
// some filter fields can be shared among devices (ex: driver, vendor, device id, pf name), but others
// can't (ex: ifname, pciaddr).
func validateFilters(this v2alpha1.CiliumNetworkDriverDevicePoolConfig, others ...v2alpha1.CiliumNetworkDriverDevicePoolConfig) error {
	for _, ifname := range this.Filter.IfNames {
		for _, otherPool := range others {
			if slices.Contains(otherPool.Filter.IfNames, ifname) {
				return fmt.Errorf("%w: %s on pools %s and %s", errIfNameInMultiplePools, ifname, this.PoolName, otherPool.PoolName)
			}
		}
	}

	for _, pciAddr := range this.Filter.PCIAddrs {
		for _, otherPool := range others {
			if slices.Contains(otherPool.Filter.PCIAddrs, pciAddr) {
				return fmt.Errorf("%w: %s on pools %s and %s", errPCIAddrInMultiplePools, pciAddr, this.PoolName, otherPool.PoolName)
			}
		}
	}

	return nil
}

// validatePools ensures that there are not any conflicting pool definitions.
func validatePools(this v2alpha1.CiliumNetworkDriverDevicePoolConfig, others ...v2alpha1.CiliumNetworkDriverDevicePoolConfig) error {
	for _, p := range others {
		if this.PoolName == p.PoolName {
			return fmt.Errorf("%w: %s", errDuplicatedPoolName, this.PoolName)
		}

		if err := validateFilters(this, others...); err != nil {
			return err
		}
	}

	return nil
}

// validateConfig ensures a configuration is sane.
func validateConfig(c v2alpha1.CiliumNetworkDriverConfigSpec) error {
	// we dont allow pool definitions that allow matching
	// the same device more than once.
	if len(c.Pools) > 1 {
		for i, p := range c.Pools {
			if err := validatePools(p, c.Pools[i+1:]...); err != nil {
				return errors.Join(errBadConfig, err)
			}
		}
	}

	return nil
}
