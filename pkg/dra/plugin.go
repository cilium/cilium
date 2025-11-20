// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dra

import (
	"context"
	"errors"
	"fmt"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// AllocatedDevice represents a network device allocated to a pod with its configuration
type AllocatedDevice struct {
	Name       string
	Attributes map[resourceapi.QualifiedName]resourceapi.DeviceAttribute
	PoolName   string
	Request    string
}

// PrepareResourceClaims is called to prepare all resources allocated for the given ResourceClaims
func (driver *Driver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (map[types.UID]kubeletplugin.PrepareResult, error) {
	if len(claims) == 0 {
		return nil, nil
	}

	results := make(map[types.UID]kubeletplugin.PrepareResult, len(claims))
	for _, claim := range claims {
		driver.logger.DebugContext(ctx, "PrepareResourceClaims: Claim Request",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)

		result, err := driver.prepareResourceClaim(ctx, claim)
		if err != nil {
			driver.logger.ErrorContext(ctx, "Failed to prepare claim",
				logfields.K8sNamespace, claim.Namespace,
				logfields.Name, claim.Name,
				logfields.Error, err,
			)
			results[claim.UID] = kubeletplugin.PrepareResult{
				Err: fmt.Errorf("claim %s/%s with UID %s contains errors: %w", claim.UID, claim.Namespace, claim.Name, err),
			}
			continue
		}
		results[claim.UID] = result
	}
	return results, nil
}

// UnprepareResourceClaims must undo whatever work PrepareResourceClaims did.
func (driver *Driver) UnprepareResourceClaims(ctx context.Context, claims []kubeletplugin.NamespacedObject) (map[types.UID]error, error) {
	if len(claims) == 0 {
		return nil, nil
	}

	result := make(map[types.UID]error, len(claims))
	for _, claim := range claims {
		driver.logger.DebugContext(ctx, "UnprepareResourceClaim: Claim Request",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)
		result[claim.UID] = driver.unprepareResourceClaim(ctx, claim)
	}

	return result, nil
}

// HandleError gets called for errors encountered in the background.
func (driver *Driver) HandleError(ctx context.Context, err error, msg string) {
	driver.logger.ErrorContext(ctx, "HandleError",
		logfields.Error, err,
		logfields.Message, msg,
	)

	// See: https://pkg.go.dev/k8s.io/apimachinery/pkg/util/runtime#HandleErrorWithContext
	runtime.HandleErrorWithContext(ctx, err, msg)
}

func (driver *Driver) prepareResourceClaim(ctx context.Context, claim *resourceapi.ResourceClaim) (kubeletplugin.PrepareResult, error) {
	// Extract pod UIDs that this claim is reserved for
	podUIDs := []types.UID{}
	for _, reference := range claim.Status.ReservedFor {
		if reference.Resource != "pods" || reference.APIGroup != "" {
			driver.logger.WarnContext(ctx, "Driver only supports Pods, unsupported reference",
				logfields.K8sNamespace, claim.Namespace,
				logfields.Name, claim.Name,
				logfields.UID, claim.UID,
				logfields.Reference, reference,
			)
			continue
		}
		podUIDs = append(podUIDs, reference.UID)
	}

	if len(podUIDs) == 0 {
		driver.logger.DebugContext(ctx, "No pods referenced by the claim",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)
		return kubeletplugin.PrepareResult{}, nil
	}

	if claim.Status.Allocation == nil || len(claim.Status.Allocation.Devices.Results) == 0 {
		driver.logger.DebugContext(ctx, "Claim has no allocated devices",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)
		return kubeletplugin.PrepareResult{}, nil
	}

	var (
		errs        []error
		allocations []AllocatedDevice
	)

	for _, allocation := range claim.Status.Allocation.Devices.Results {
		// filter out devices not managed by this driver
		if allocation.Driver != driver.name {
			continue
		}

		// get device attributes from published resources
		deviceAttrs, err := driver.getDeviceAttributes(ctx, allocation.Device)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get attributes for device %s: %w", allocation.Device, err))
			continue
		}

		device := AllocatedDevice{
			Name:       allocation.Device,
			Attributes: deviceAttrs,
			PoolName:   allocation.Pool,
			Request:    allocation.Request,
		}
		allocations = append(allocations, device)

		driver.logger.DebugContext(ctx, "Prepared device for claim",
			logfields.Device, allocation.Device,
			logfields.Attributes, deviceAttrs,
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
		)
	}

	// Store device configuration for all referenced pods
	driver.lock.Lock()
	defer driver.lock.Unlock()
	for _, podUID := range podUIDs {
		driver.podDeviceConfig[podUID] = append(driver.podDeviceConfig[podUID], allocations...)
		driver.logger.DebugContext(ctx, "Prepared devices for pod",
			logfields.UID, podUID,
			logfields.Devices, len(allocations),
		)
	}

	return kubeletplugin.PrepareResult{}, errors.Join(errs...)
}

func (driver *Driver) getDeviceAttributes(ctx context.Context, target string) (map[resourceapi.QualifiedName]resourceapi.DeviceAttribute, error) {
	// Get fresh device list to find attributes
	devices, err := driver.listDevices(ctx, driver.logger, driver.toQualifiedName)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	for _, device := range devices {
		if device.Name == target {
			return device.Attributes, nil
		}
	}

	return nil, fmt.Errorf("device %s not found in available devices", target)
}

func (driver *Driver) unprepareResourceClaim(ctx context.Context, claim kubeletplugin.NamespacedObject) error {
	driver.lock.Lock()
	defer driver.lock.Unlock()

	devices, ok := driver.podDeviceConfig[claim.UID]
	if !ok {
		driver.logger.DebugContext(ctx, "UnprepareResourceClaim: no devices allocated for claim",
			logfields.K8sNamespace, claim.Namespace,
			logfields.Name, claim.Name,
			logfields.UID, claim.UID,
		)
		return nil
	}

	delete(driver.podDeviceConfig, claim.UID)
	driver.logger.DebugContext(ctx, "UnprepareResourceClaim completed for claim",
		logfields.K8sNamespace, claim.Namespace,
		logfields.Name, claim.Name,
		logfields.UID, claim.UID,
		logfields.NumDevices, len(devices),
	)

	return nil
}
