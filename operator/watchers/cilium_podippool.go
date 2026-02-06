// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// PooledAllocatorProvider defines the functions of IPAM provider front-end which additionally allow
// definition of IP pools at runtime.
// This is implemented by e.g. pkg/ipam/allocator/multipool
type PooledAllocatorProvider interface {
	UpsertPool(ctx context.Context, pool *cilium_v2.CiliumPodIPPool) error
	DeletePool(ctx context.Context, pool *cilium_v2.CiliumPodIPPool) error
}

const (
	poolKeyIPv4CIDRs    = "ipv4-cidrs"
	poolKeyIPv4MaskSize = "ipv4-mask-size"
	poolKeyIPv6CIDRs    = "ipv6-cidrs"
	poolKeyIPv6MaskSize = "ipv6-mask-size"
)

// parsePoolSpec parses a pool spec string in the form
// "ipv4-cidrs:172.16.0.0/16,172.17.0.0/16;ipv4-mask-size:24".
func parsePoolSpec(poolString string) (cilium_v2.IPPoolSpec, error) {
	fields := strings.FieldsFunc(strings.ReplaceAll(poolString, " ", ""), func(c rune) bool {
		return c == ';'
	})

	var ipv4CIDRs, ipv6CIDRs []cilium_v2.PoolCIDR
	var ipv4MaskSize, ipv6MaskSize uint8

	for _, field := range fields {
		key, value, ok := strings.Cut(field, ":")
		if !ok {
			return cilium_v2.IPPoolSpec{}, fmt.Errorf("invalid number of key delimiters in pool spec %s", poolString)
		}
		switch key {
		case poolKeyIPv4CIDRs:
			for cidr := range strings.SplitSeq(value, ",") {
				_, err := netip.ParsePrefix(cidr)
				if err != nil {
					return cilium_v2.IPPoolSpec{}, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4CIDRs, err)
				}
				ipv4CIDRs = append(ipv4CIDRs, cilium_v2.PoolCIDR{CIDR: cidr})
			}
		case poolKeyIPv4MaskSize:
			mask, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return cilium_v2.IPPoolSpec{}, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4MaskSize, err)
			}
			ipv4MaskSize = uint8(mask)
		case poolKeyIPv6CIDRs:
			for cidr := range strings.SplitSeq(value, ",") {
				_, err := netip.ParsePrefix(cidr)
				if err != nil {
					return cilium_v2.IPPoolSpec{}, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv6CIDRs, err)
				}
				ipv6CIDRs = append(ipv6CIDRs, cilium_v2.PoolCIDR{CIDR: cidr})
			}
		case poolKeyIPv6MaskSize:
			mask, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return cilium_v2.IPPoolSpec{}, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv6MaskSize, err)
			}
			ipv6MaskSize = uint8(mask)
		}
	}

	pool := cilium_v2.IPPoolSpec{}
	if len(ipv4CIDRs) > 0 {
		pool.IPv4 = &cilium_v2.IPv4PoolSpec{
			CIDRs:    ipv4CIDRs,
			MaskSize: ipv4MaskSize,
		}
	}
	if len(ipv6CIDRs) > 0 {
		pool.IPv6 = &cilium_v2.IPv6PoolSpec{
			CIDRs:    ipv6CIDRs,
			MaskSize: ipv6MaskSize,
		}
	}

	return pool, nil
}

func multiPoolAutoCreatePools(ctx context.Context, clientset client.Clientset, poolMap map[string]string, logger *slog.Logger) {
	for poolName, poolSpecStr := range poolMap {
		poolSpec, err := parsePoolSpec(poolSpecStr)
		if err != nil {
			logger.ErrorContext(ctx,
				fmt.Sprintf("Failed to parse IP pool spec in %q flag", operatorOption.IPAMAutoCreateCiliumPodIPPools),
				logfields.PoolName, poolName,
				logfields.PoolSpec, poolSpecStr,
				logfields.Error, err)
			os.Exit(1)
		}

		pool := &cilium_v2.CiliumPodIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: poolName,
			},
			Spec: poolSpec,
		}

		_, err = clientset.CiliumV2().CiliumPodIPPools().Create(ctx, pool, metav1.CreateOptions{})
		if err != nil {
			if k8sErrors.IsAlreadyExists(err) {
				// Nothing to do, we will not try to update an existing resource
				logger.InfoContext(ctx,
					"Found existing CiliumPodIPPool resource. Skipping creation",
					logfields.PoolName, poolName)
			} else {
				logger.ErrorContext(ctx,
					"Failed to create CiliumPodIPPool resource",
					logfields.PoolName, poolName,
					logfields.Object, pool,
					logfields.Error, err)
			}
			continue
		}

		logger.InfoContext(ctx, "Created CiliumPodIPPool resource", logfields.PoolName, poolName)
	}
}

// convertV2Alpha1ToV2 converts a v2alpha1 CiliumPodIPPool to v2 format.
func convertV2Alpha1ToV2(pool *cilium_v2alpha1.CiliumPodIPPool) *cilium_v2.CiliumPodIPPool {
	v2Pool := &cilium_v2.CiliumPodIPPool{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumPodIPPool",
		},
	}

	v2Pool.Spec.PodSelector = pool.Spec.PodSelector.DeepCopy()
	v2Pool.Spec.NamespaceSelector = pool.Spec.NamespaceSelector.DeepCopy()
	pool.ObjectMeta.DeepCopyInto(&v2Pool.ObjectMeta)

	// Clear server-managed fields that should not be set on new objects
	v2Pool.ObjectMeta.ResourceVersion = ""
	v2Pool.ObjectMeta.UID = ""
	v2Pool.ObjectMeta.CreationTimestamp = metav1.Time{}

	// Convert IPv4 spec
	if pool.Spec.IPv4 != nil {
		v2Pool.Spec.IPv4 = &cilium_v2.IPv4PoolSpec{
			MaskSize: pool.Spec.IPv4.MaskSize,
		}
		for _, cidr := range pool.Spec.IPv4.CIDRs {
			// Skip empty CIDRs (happens when v2 data is read via v2alpha1 API)
			if string(cidr) == "" {
				continue
			}
			v2Pool.Spec.IPv4.CIDRs = append(v2Pool.Spec.IPv4.CIDRs, cilium_v2.PoolCIDR{
				CIDR: string(cidr),
			})
		}
	}

	// Convert IPv6 spec
	if pool.Spec.IPv6 != nil {
		v2Pool.Spec.IPv6 = &cilium_v2.IPv6PoolSpec{
			MaskSize: pool.Spec.IPv6.MaskSize,
		}
		for _, cidr := range pool.Spec.IPv6.CIDRs {
			// Skip empty CIDRs (happens when v2 data is read via v2alpha1 API)
			if string(cidr) == "" {
				continue
			}
			v2Pool.Spec.IPv6.CIDRs = append(v2Pool.Spec.IPv6.CIDRs, cilium_v2.PoolCIDR{
				CIDR: string(cidr),
			})
		}
	}

	return v2Pool
}

const (
	// AnnotationDisableMigration is the annotation key to disable automatic migration from v2alpha1 to v2.
	// By default, the operator will automatically migrate v2alpha1 CiliumPodIPPool resources to v2.
	// Set this annotation to "true" to prevent automatic migration.
	AnnotationDisableMigration = "cilium.io/ipam-disable-migration"
)

func StartIPPoolAllocator(
	ctx context.Context,
	clientset client.Clientset,
	allocator PooledAllocatorProvider,
	ipPoolsV2 resource.Resource[*cilium_v2.CiliumPodIPPool],
	logger *slog.Logger,
) {
	logger.InfoContext(ctx, "Starting CiliumPodIPPool allocator watcher")

	multiPoolAutoCreatePools(ctx, clientset, operatorOption.Config.IPAMAutoCreateCiliumPodIPPools, logger)

	synced := make(chan struct{})

	go func() {
		for ev := range ipPoolsV2.Events(ctx) {
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
				logger.ErrorContext(ctx, fmt.Sprintf("failed to %s pool %q", action, ev.Key.Name), logfields.Error, err)
			}
		}
	}()

	<-synced
	logger.InfoContext(ctx, "All CiliumPodIPPool V2 resources synchronized")
}

// StartIPPoolMigrator watches V2Alpha1 CiliumPodIPPool resources and migrates them to V2.
// Migration is automatic by default. Set AnnotationDisableMigration to "true" to prevent migration.
func StartIPPoolMigrator(
	ctx context.Context,
	clientset client.Clientset,
	ipPoolsV2alpha1 resource.Resource[*cilium_v2alpha1.CiliumPodIPPool],
	logger *slog.Logger,
) {
	logger.InfoContext(ctx, "Starting CiliumPodIPPool migrator")

	synced := make(chan struct{})

	go func() {
		for ev := range ipPoolsV2alpha1.Events(ctx) {
			switch ev.Kind {
			case resource.Sync:
				close(synced)
			case resource.Upsert:
				// Skip migration if disabled via annotation
				if val, ok := ev.Object.Annotations[AnnotationDisableMigration]; ok && val == "true" {
					logger.DebugContext(ctx, "Migration disabled via annotation, skipping", logfields.PoolName, ev.Key.Name)
					ev.Done(nil)
					continue
				}

				v2Pool := convertV2Alpha1ToV2(ev.Object)
				// Skip if conversion returned nil (pool already in v2 format, no valid CIDRs)
				if v2Pool == nil {
					logger.DebugContext(ctx, "Pool has no valid CIDRs (likely already v2), skipping migration", logfields.PoolName, ev.Key.Name)
					ev.Done(nil)
					continue
				}

				_, createErr := clientset.CiliumV2().CiliumPodIPPools().Create(ctx, v2Pool, metav1.CreateOptions{})
				if createErr != nil {
					if k8sErrors.IsAlreadyExists(createErr) {
						logger.DebugContext(ctx, "V2 pool already exists, skipping migration", logfields.PoolName, ev.Key.Name)
					} else {
						logger.WarnContext(ctx, "Failed to migrate pool to v2",
							logfields.PoolName, ev.Key.Name,
							logfields.Error, createErr,
						)
					}
				} else {
					logger.InfoContext(ctx, "Successfully migrated pool to v2", logfields.PoolName, ev.Key.Name)
				}
			case resource.Delete:
				logger.DebugContext(ctx, "V2Alpha1 pool deleted, V2 pool not affected", logfields.PoolName, ev.Key.Name)
			}

			ev.Done(nil)
		}
	}()

	<-synced
	logger.InfoContext(ctx, "All CiliumPodIPPool V2Alpha1 resources synchronized")
}
