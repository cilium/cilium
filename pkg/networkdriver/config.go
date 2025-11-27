// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/time"
)

// PoolConfig represents a pool of similar resources.
// Each pool of resources is announced as a ResourceSlice
// Kubernetes resource, allowing pods to claim resources from it.
type PoolConfig struct {
	// Pool names must be unique
	Name   string
	Filter types.DeviceFilter
}

type Config struct {
	DraRegistrationRetry   time.Duration
	DraRegistrationTimeout time.Duration
	PublishInterval        time.Duration
	DriverName             string
	DeviceManagerConfigs   map[types.DeviceManagerType]types.DeviceManagerConfig
	Pools                  []PoolConfig
}

// validateFilters ensures that we do not have more than one filter matching the same device.
// some filter fields can be shared among devices (ex: driver, vendor, device id, pf name), but others
// can't (ex: ifname, pciaddr).
func validateFilters(this PoolConfig, others ...PoolConfig) error {
	for _, ifname := range this.Filter.IfNames {
		for _, otherPool := range others {
			if slices.Contains(otherPool.Filter.IfNames, ifname) {
				return fmt.Errorf("%w: %s on pools %s and %s", errIfNameInMultiplePools, ifname, this.Name, otherPool.Name)
			}
		}
	}

	for _, pciAddr := range this.Filter.PciAddrs {
		for _, otherPool := range others {
			if slices.Contains(otherPool.Filter.PciAddrs, pciAddr) {
				return fmt.Errorf("%w: %s on pools %s and %s", errPCIAddrInMultiplePools, pciAddr, this.Name, otherPool.Name)
			}
		}
	}

	return nil
}

// validatePools ensures that there are not any conflicting pool definitions.
func validatePools(this PoolConfig, others ...PoolConfig) error {
	for _, p := range others {
		if this.Name == p.Name {
			return fmt.Errorf("%w: %s", errDuplicatedPoolName, this.Name)
		}

		if err := validateFilters(this, others...); err != nil {
			return err
		}
	}

	return nil
}

// Validate ensures a configuration is sane.
func (c *Config) Validate() error {
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
