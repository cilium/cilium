// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clusterpool

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/ipam/cidrset"
	"github.com/sirupsen/logrus"

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
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-clusterpool")

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
func (a *AllocatorOperator) Init(ctx context.Context) error {
	if option.Config.EnableIPv4 {
		if len(operatorOption.Config.ClusterPoolIPv4CIDR) == 0 {
			return fmt.Errorf("%s must be provided when using ClusterPool", operatorOption.ClusterPoolIPv4CIDR)
		}

		v4Allocators, err := newCIDRSets(false, operatorOption.Config.ClusterPoolIPv4CIDR, operatorOption.Config.NodeCIDRMaskSizeIPv4)
		if err != nil {
			return fmt.Errorf("unable to initialize IPv4 allocator %w", err)
		}
		a.v4CIDRSet = v4Allocators
	} else if len(operatorOption.Config.ClusterPoolIPv4CIDR) != 0 {
		return fmt.Errorf("%s must not be set if IPv4 is disabled", operatorOption.ClusterPoolIPv4CIDR)
	}

	if option.Config.EnableIPv6 {
		if len(operatorOption.Config.ClusterPoolIPv6CIDR) == 0 {
			return fmt.Errorf("%s must be provided when using ClusterPool", operatorOption.ClusterPoolIPv6CIDR)
		}

		v6Allocators, err := newCIDRSets(true, operatorOption.Config.ClusterPoolIPv6CIDR, operatorOption.Config.NodeCIDRMaskSizeIPv6)
		if err != nil {
			return fmt.Errorf("unable to initialize IPv6 allocator %w", err)
		}
		a.v6CIDRSet = v6Allocators
	} else if len(operatorOption.Config.ClusterPoolIPv6CIDR) != 0 {
		return fmt.Errorf("%s must not be set if IPv6 is disabled", operatorOption.ClusterPoolIPv6CIDR)
	}

	return nil
}

// Start kicks of Operator allocation.
func (a *AllocatorOperator) Start(ctx context.Context, updater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	log.WithFields(logrus.Fields{
		logfields.IPv4CIDRs: operatorOption.Config.ClusterPoolIPv4CIDR,
		logfields.IPv6CIDRs: operatorOption.Config.ClusterPoolIPv6CIDR,
	}).Info("Starting ClusterPool IP allocator")

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
