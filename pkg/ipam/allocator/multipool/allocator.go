// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// Allocator implements allocator.AllocatorProvider
type Allocator struct {
	poolAlloc *PoolAllocator
}

type poolSpec struct {
	ipv4CIDRs    []string
	ipv6CIDRs    []string
	ipv4MaskSize int
	ipv6MaskSize int
}

const (
	poolKeyIPv4CIDRs    = "ipv4-cidrs"
	poolKeyIPv4MaskSize = "ipv4-mask-size"
	poolKeyIPv6CIDRs    = "ipv6-cidrs"
	poolKeyIPv6MaskSize = "ipv6-mask-size"
)

// parsePoolSpec parses a pool spec string in the form
// "ipv4-cidrs:172.16.0.0/16,172.17.0.0/16;ipv4-mask-size:24".
func parsePoolSpec(poolString string) (poolSpec, error) {
	fields := strings.Split(strings.ReplaceAll(poolString, " ", ""), ";")

	var pool poolSpec
	for _, field := range fields {
		key, value, ok := strings.Cut(field, ":")
		if !ok {
			return pool, fmt.Errorf("invalid number of key delimiters in pool spec %s", poolString)
		}
		switch key {
		case poolKeyIPv4CIDRs:
			pool.ipv4CIDRs = strings.Split(value, ",")
			// TODO: validate individual CIDRs?
		case poolKeyIPv4MaskSize:
			mask, err := strconv.Atoi(value)
			if err != nil {
				return pool, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4MaskSize, err)
			}
			pool.ipv4MaskSize = mask
		case poolKeyIPv6CIDRs:
			pool.ipv6CIDRs = strings.Split(value, ",")
		case poolKeyIPv6MaskSize:
			mask, err := strconv.Atoi(value)
			if err != nil {
				return pool, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4MaskSize, err)
			}
			pool.ipv6MaskSize = mask
		}
	}
	return pool, nil
}

func (a *Allocator) Init(ctx context.Context) (err error) {
	a.poolAlloc = NewPoolAllocator()

	for poolName, pool := range operatorOption.Config.IPAMMultiPoolMap {
		log.WithFields(logrus.Fields{
			"pool-name": poolName,
			"pool":      pool,
		}).Debug("found pool definition")

		pool, parseErr := parsePoolSpec(pool)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("failed to parse IP pool spec for pool %s: %w", poolName, parseErr))
			continue
		}

		log.WithFields(logrus.Fields{
			"pool-name":      poolName,
			"ipv4-cidrs":     pool.ipv4CIDRs,
			"ipv4-mask-size": pool.ipv4MaskSize,
			"ipv6-cidrs":     pool.ipv6CIDRs,
			"ipv6-mask-size": pool.ipv6MaskSize,
		}).Debug("adding pool")
		if addErr := a.poolAlloc.AddPool(poolName, pool.ipv4CIDRs, pool.ipv4MaskSize, pool.ipv6CIDRs, pool.ipv6MaskSize); addErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to add IP pool %s to allocator: %w", poolName, addErr))
			continue
		}
	}

	return err
}

func (a *Allocator) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	return NewNodeHandler(a.poolAlloc, getterUpdater), nil
}

func (a *Allocator) UpsertPool(ctx context.Context, pool *cilium_v2alpha1.CiliumPodIPPool) error {
	log.WithFields(logrus.Fields{
		"pool-name":      pool.Name,
		"ipv4-cidrs":     pool.Spec.IPv4.CIDRs,
		"ipv4-mask-size": pool.Spec.IPv4.MaskSize,
		"ipv6-cidrs":     pool.Spec.IPv6.CIDRs,
		"ipv6-mask-size": pool.Spec.IPv6.MaskSize,
	}).Debug("upserting pool")

	ipv4CIDRs := make([]string, len(pool.Spec.IPv4.CIDRs))
	for i, cidr := range pool.Spec.IPv4.CIDRs {
		ipv4CIDRs[i] = string(cidr)
	}
	ipv6CIDRs := make([]string, len(pool.Spec.IPv6.CIDRs))
	for i, cidr := range pool.Spec.IPv6.CIDRs {
		ipv6CIDRs[i] = string(cidr)
	}

	return a.poolAlloc.UpsertPool(
		pool.Name,
		ipv4CIDRs,
		int(pool.Spec.IPv4.MaskSize),
		ipv6CIDRs,
		int(pool.Spec.IPv6.MaskSize),
	)
}

func (a *Allocator) DeletePool(ctx context.Context, pool *cilium_v2alpha1.CiliumPodIPPool) error {
	log.WithFields(logrus.Fields{
		"pool-name": pool.Name,
	}).Debug("deleting pool")

	return a.poolAlloc.DeletePool(pool.Name)
}
