// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
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
func validateConfig(c *v2alpha1.CiliumNetworkDriverConfigSpec) error {
	if c == nil {
		// empty config is valid
		return nil
	}

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

func labelsMatch(config *v2alpha1.CiliumNetworkDriverConfig, nodeLabels map[string]string) (bool, error) {
	l := labels.Set(nodeLabels)

	selector, err := metav1.LabelSelectorAsSelector(config.Spec.NodeSelector)
	if err != nil {
		return false, err
	}

	return selector.Matches(l), nil
}

// selectConfig decides which config to choose among a set of configs
// 1- selects most specific match - configuration with more selectors wins
// 2- if two configs have the same amount of selectors, choose the oldest one
// 3- fallback to config with no selectors
func selectConfig(configs []*v2alpha1.CiliumNetworkDriverConfig) *v2alpha1.CiliumNetworkDriverConfig {
	var selected *v2alpha1.CiliumNetworkDriverConfig

	for _, c := range configs {
		switch {
		case selected == nil:
			selected = c.DeepCopy()
		case c.Spec.NodeSelector.Size() > selected.Spec.NodeSelector.Size():
			selected = c.DeepCopy()
		case c.Spec.NodeSelector.Size() == selected.Spec.NodeSelector.Size():
			// it's a tie? get the oldest
			if c.GetCreationTimestamp().Time.Before(selected.GetCreationTimestamp().Time) {
				selected = c.DeepCopy()
			}
		}
	}

	return selected
}
