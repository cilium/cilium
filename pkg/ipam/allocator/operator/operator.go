// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package operator

import (
	"errors"
	"fmt"
	"net"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	ipPkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	"github.com/cilium/cilium/pkg/ipam/allocator/podcidr"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/cilium/ipam/cidrset"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-operator")

type ErrCIDRColision struct {
	cidr      string
	allocator podcidr.CIDRAllocator
}

func (e ErrCIDRColision) Error() string {
	return fmt.Sprintf("requested CIDR %s colides with %s", e.cidr, e.allocator)
}

func (e *ErrCIDRColision) Is(target error) bool {
	t, ok := target.(*ErrCIDRColision)
	if !ok {
		return false
	}
	return t.cidr == e.cidr
}

// AllocatorOperator is an implementation of IPAM allocator interface for Cilium
// IPAM.
type AllocatorOperator struct {
	v4CIDRSet, v6CIDRSet []podcidr.CIDRAllocator
}

// Init sets up Cilium allocator based on given options
func (a *AllocatorOperator) Init() error {
	if len(operatorOption.Config.ClusterPoolIPv4CIDR) != 0 {
		if !option.Config.EnableIPv4 {
			return errors.New("IPv4CIDR can not be set if IPv4 is not enabled")
		}
		v4Allocators, err := newCIDRSets(false, operatorOption.Config.ClusterPoolIPv4CIDR, operatorOption.Config.NodeCIDRMaskSizeIPv4)
		if err != nil {
			return fmt.Errorf("unable to initialize IPv4 allocator %w", err)
		}
		a.v4CIDRSet = v4Allocators
	}
	if len(operatorOption.Config.ClusterPoolIPv6CIDR) != 0 {
		if !option.Config.EnableIPv6 {
			return errors.New("IPv6CIDR can not be set if IPv6 is not enabled")
		}
		v6Allocators, err := newCIDRSets(true, operatorOption.Config.ClusterPoolIPv6CIDR, operatorOption.Config.NodeCIDRMaskSizeIPv6)
		if err != nil {
			return fmt.Errorf("unable to initialize IPv6 allocator %w", err)
		}
		a.v6CIDRSet = v6Allocators
	}
	if len(a.v4CIDRSet)+len(a.v6CIDRSet) == 0 {
		return fmt.Errorf("either '%s' or '%s' need to be set", operatorOption.ClusterPoolIPv4CIDR, operatorOption.ClusterPoolIPv6CIDR)
	}
	return nil
}

// Start kicks of Operator allocation.
func (a *AllocatorOperator) Start(updater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	log.Info("Starting Operator IP allocator...")

	var (
		iMetrics trigger.MetricsObserver
	)

	if operatorOption.Config.EnableMetrics {
		iMetrics = ipamMetrics.NewTriggerMetrics(operatorMetrics.Namespace, "k8s_sync")
	} else {
		iMetrics = &ipamMetrics.NoOpMetricsObserver{}
	}

	nodeManager := podcidr.NewNodesPodCIDRManager(a.v4CIDRSet, a.v6CIDRSet, updater, iMetrics)

	return nodeManager, nil
}

func newCIDRSets(isV6 bool, strCIDRs []string, maskSize int) ([]podcidr.CIDRAllocator, error) {
	cidrAllocators := make([]podcidr.CIDRAllocator, 0, len(strCIDRs))
	for _, strCIDR := range strCIDRs {
		addr, cidr, err := net.ParseCIDR(strCIDR)
		if err != nil {
			return nil, err
		}
		// Check if CIDRs collide with each other.
		for _, cidrAllocator := range cidrAllocators {
			if cidrAllocator.InRange(cidr) {
				return nil, &ErrCIDRColision{
					cidr:      strCIDR,
					allocator: cidrAllocator,
				}
			}
		}
		cidrSet, err := newCIDRSet(isV6, addr, cidr, maskSize)
		if err != nil {
			return nil, err
		}
		cidrAllocators = append(cidrAllocators, cidrSet)
	}
	return cidrAllocators, nil
}

func newCIDRSet(isV6 bool, addr net.IP, cidr *net.IPNet, maskSize int) (podcidr.CIDRAllocator, error) {
	switch {
	case isV6 && ipPkg.IsIPv4(addr):
		return nil, fmt.Errorf("CIDR is not v6 family: %s", cidr)
	case !isV6 && !ipPkg.IsIPv4(addr):
		return nil, fmt.Errorf("CIDR is not v4 family: %s", cidr)
	}

	return cidrset.NewCIDRSet(cidr, maskSize)
}
