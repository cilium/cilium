// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// PooledAllocatorProvider defines the functions of IPAM provider front-end which additionally allow
// definition of IP pools at runtime.
// This is implemented by e.g. pkg/ipam/allocator/multipool
type PooledAllocatorProvider interface {
	UpsertPool(ctx context.Context, pool *cilium_v2alpha1.CiliumPodIPPool) error
	DeletePool(ctx context.Context, pool *cilium_v2alpha1.CiliumPodIPPool) error
}

const (
	poolKeyIPv4CIDRs    = "ipv4-cidrs"
	poolKeyIPv4MaskSize = "ipv4-mask-size"
	poolKeyIPv6CIDRs    = "ipv6-cidrs"
	poolKeyIPv6MaskSize = "ipv6-mask-size"
)

// parsePoolSpec parses a pool spec string in the form
// "ipv4-cidrs:172.16.0.0/16,172.17.0.0/16;ipv4-mask-size:24".
func parsePoolSpec(poolString string) (cilium_v2alpha1.IPPoolSpec, error) {
	fields := strings.FieldsFunc(strings.ReplaceAll(poolString, " ", ""), func(c rune) bool {
		return c == ';'
	})

	var ipv4CIDRs, ipv6CIDRs []cilium_v2alpha1.PoolCIDR
	var ipv4MaskSize, ipv6MaskSize uint8

	for _, field := range fields {
		key, value, ok := strings.Cut(field, ":")
		if !ok {
			return cilium_v2alpha1.IPPoolSpec{}, fmt.Errorf("invalid number of key delimiters in pool spec %s", poolString)
		}
		switch key {
		case poolKeyIPv4CIDRs:
			for _, cidr := range strings.Split(value, ",") {
				_, err := netip.ParsePrefix(cidr)
				if err != nil {
					return cilium_v2alpha1.IPPoolSpec{}, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4CIDRs, err)
				}
				ipv4CIDRs = append(ipv4CIDRs, cilium_v2alpha1.PoolCIDR(cidr))
			}
		case poolKeyIPv4MaskSize:
			mask, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return cilium_v2alpha1.IPPoolSpec{}, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4MaskSize, err)
			}
			ipv4MaskSize = uint8(mask)
		case poolKeyIPv6CIDRs:
			for _, cidr := range strings.Split(value, ",") {
				_, err := netip.ParsePrefix(cidr)
				if err != nil {
					return cilium_v2alpha1.IPPoolSpec{}, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv6CIDRs, err)
				}
				ipv6CIDRs = append(ipv6CIDRs, cilium_v2alpha1.PoolCIDR(cidr))
			}
		case poolKeyIPv6MaskSize:
			mask, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return cilium_v2alpha1.IPPoolSpec{}, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv6MaskSize, err)
			}
			ipv6MaskSize = uint8(mask)
		}
	}

	pool := cilium_v2alpha1.IPPoolSpec{}
	if len(ipv4CIDRs) > 0 {
		pool.IPv4 = &cilium_v2alpha1.IPv4PoolSpec{
			CIDRs:    ipv4CIDRs,
			MaskSize: ipv4MaskSize,
		}
	}
	if len(ipv6CIDRs) > 0 {
		pool.IPv6 = &cilium_v2alpha1.IPv6PoolSpec{
			CIDRs:    ipv6CIDRs,
			MaskSize: ipv6MaskSize,
		}
	}

	return pool, nil
}

func multiPoolAutoCreatePools(ctx context.Context, clientset client.Clientset, poolMap map[string]string) {
	for poolName, poolSpecStr := range poolMap {
		poolSpec, err := parsePoolSpec(poolSpecStr)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"poolName": poolName,
				"poolSpec": poolSpecStr,
			}).Fatalf("Failed to parse IP pool spec in %q flag", operatorOption.IPAMAutoCreateCiliumPodIPPools)
		}

		pool := &cilium_v2alpha1.CiliumPodIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: poolName,
			},
			Spec: poolSpec,
		}

		_, err = clientset.CiliumV2alpha1().CiliumPodIPPools().Create(ctx, pool, metav1.CreateOptions{})
		if err != nil {
			if k8sErrors.IsAlreadyExists(err) {
				// Nothing to do, we will not try to update an existing resource
				log.WithField("poolName", poolName).Info("Found existing CiliumPodIPPool resource. Skipping creation")
			} else {
				log.WithError(err).WithField("poolName", poolName).WithField("obj", pool).Error("Failed to create CiliumPodIPPool resource")
			}
			continue
		}

		log.WithField("poolName", poolName).Info("Created CiliumPodIPPool resource")
	}
}

func StartIPPoolAllocator(
	ctx context.Context,
	clientset client.Clientset,
	allocator PooledAllocatorProvider,
	ipPools resource.Resource[*cilium_v2alpha1.CiliumPodIPPool],
) {
	log.Info("Starting CiliumPodIPPool allocator watcher")

	multiPoolAutoCreatePools(ctx, clientset, operatorOption.Config.IPAMAutoCreateCiliumPodIPPools)

	synced := make(chan struct{})

	go func() {
		for ev := range ipPools.Events(ctx) {
			var err error
			var action string

			switch ev.Kind {
			case resource.Sync:
				close(synced)
			case resource.Upsert:
				err = allocator.UpsertPool(ctx, ev.Object)
				action = "upsert"
			case resource.Delete:
				err = allocator.DeletePool(ctx, ev.Object)
				action = "delete"
			}
			ev.Done(err)
			if err != nil {
				log.WithError(err).Errorf("failed to %s pool %q", action, ev.Key)
			}
		}
	}()

	// Block until all pools are restored, so callers can safely start node allocation
	// right after return.
	<-synced
	log.Info("All CiliumPodIPPool resources synchronized")
}
