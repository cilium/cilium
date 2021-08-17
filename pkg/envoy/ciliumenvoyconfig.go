// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"time"

	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/option"
)

// Resources contains all Envoy resources parsed from a CiliumEnvoyConfig CRD
type Resources struct {
	Listeners []*envoy_config_listener.Listener
}

// ParseResources parses all supported Envoy resource types from CiliumEnvoyConfig CRD to Resources type
func ParseResources(namePrefix string, cec *cilium_v2alpha1.CiliumEnvoyConfig) (Resources, error) {
	resources := Resources{}
	names := make(map[string]struct{})
	for _, r := range cec.Spec.Resources {
		message, err := r.UnmarshalNew()
		if err != nil {
			return Resources{}, err
		}
		name := ""
		typeURL := r.GetTypeUrl()
		switch typeURL {
		case "type.googleapis.com/envoy.config.listener.v3.Listener":
			listener, ok := message.(*envoy_config_listener.Listener)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Listener: %T", message)
			}
			if listener.GetAddress() == nil {
				return Resources{}, fmt.Errorf("Listener has no address: %T", message)
			}

			if option.Config.EnableBPFTProxy {
				// Envoy since 1.20.0 uses SO_REUSEPORT on listeners by default.
				// BPF TPROXY is currently not compatible with SO_REUSEPORT, so
				// disable it.  Note that this may degrade Envoy performance.
				listener.EnableReusePort = &wrapperspb.BoolValue{Value: false}
			}

			resources.Listeners = append(resources.Listeners, listener)
			name = listener.Name
			listener.Name = namePrefix + "/" + listener.Name // Prepend listener name with k8s resource name

			log.Debugf("ParseResources: Parsed listener %s: %v", name, listener)

		default:
			return Resources{}, fmt.Errorf("Unsupported type: %s", typeURL)
		}
		if name == "" {
			return Resources{}, fmt.Errorf("Unnamed resource: %v", message)
		}
		if _, exists := names[name]; exists {
			return Resources{}, fmt.Errorf("Duplicate resource name %q", name)
		}
		names[name] = struct{}{}
	}
	if len(resources.Listeners) == 0 {
		log.Debugf("ParseResources: No listeners parsed from %v", cec.Spec)
	}
	return resources, nil
}

// UpsertEnvoyResources inserts or updates Envoy resources in 'resources' to the xDS cache,
// from where they will be delivered to Envoy via xDS streaming gRPC.
func (s *XDSServer) UpsertEnvoyResources(ctx context.Context, resources Resources) error {
	log.Debugf("UpsertEnvoyResources: Upserting %d listeners...", len(resources.Listeners))
	wg := completion.NewWaitGroup(ctx)
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	for i := range resources.Listeners {
		revertFuncs = append(revertFuncs, s.upsertListener(resources.Listeners[i].Name, resources.Listeners[i], wg, nil))
	}

	start := time.Now()
	log.Debug("UpsertEnvoyResources: Waiting for proxy updates to complete...")
	err := wg.Wait()
	log.Debug("UpsertEnvoyResources: Wait time for proxy updates: ", time.Since(start))

	// revert all changes in case of failure
	if err != nil {
		revertFuncs.Revert(nil)
		log.Debug("UpsertEnvoyResources: Finished reverting failed xDS transactions")
	}
	return err
}

// UpdateEnvoyResources removes any resources in 'old' that are not
// present in 'new' and then adds or updates all resources in 'new'.
// Envoy does not support changing the listening port of an existing
// listener, so if the port changes we have to delete the old listener
// and then add the new one with the new port number.
func (s *XDSServer) UpdateEnvoyResources(ctx context.Context, old, new Resources) error {
	waitForDelete := false
	wg := completion.NewWaitGroup(ctx)
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	// Delete old listeners not added in 'new' or if old and new listener have different ports
	var deleteListeners []*envoy_config_listener.Listener
	for _, oldListener := range old.Listeners {
		found := false
		port := uint32(0)
		if addr := oldListener.Address.GetSocketAddress(); addr != nil {
			port = addr.GetPortValue()
		}
		for _, newListener := range new.Listeners {
			if newListener.Name == oldListener.Name {
				if addr := newListener.Address.GetSocketAddress(); addr != nil && addr.GetPortValue() != port {
					log.Debugf("UpdateEnvoyResources: %s port changing from %d to %d...", newListener.Name, port, addr.GetPortValue())
					waitForDelete = true
				} else {
					found = true
				}
				break
			}
		}
		if !found {
			deleteListeners = append(deleteListeners, oldListener)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d listeners...", len(deleteListeners), len(new.Listeners))
	for _, listener := range deleteListeners {
		revertFuncs = append(revertFuncs, s.deleteListener(listener.Name, wg, nil))
	}

	// Have to wait for deletes to complete before adding new listeners if a listener's port number is changed.
	if waitForDelete {
		start := time.Now()
		log.Debug("UpdateEnvoyResources: Waiting for proxy deletes to complete...")
		err := wg.Wait()
		if err != nil {
			log.Debug("UpdateEnvoyResources: delete failed: ", err)
		}
		log.Debug("UpdateEnvoyResources: Wait time for proxy deletes: ", time.Since(start))
		// new wait group for adds
		wg = completion.NewWaitGroup(ctx)
	}

	// Add new listeners
	for i := range new.Listeners {
		revertFuncs = append(revertFuncs, s.upsertListener(new.Listeners[i].Name, new.Listeners[i], wg, nil))
	}

	start := time.Now()
	log.Debug("UpdateEnvoyResources: Waiting for proxy updates to complete...")
	err := wg.Wait()
	log.Debug("UpdateEnvoyResources: Wait time for proxy updates: ", time.Since(start))

	// revert all changes in case of failure
	if err != nil {
		revertFuncs.Revert(nil)
		log.Debug("UpdateEnvoyResources: Finished reverting failed xDS transactions")
	}
	return err
}

// DeleteEnvoyResources deletes all Envoy resources in 'resources'.
func (s *XDSServer) DeleteEnvoyResources(ctx context.Context, resources Resources) error {
	log.Debugf("UpdateEnvoyResources: Deleting %d listeners...", len(resources.Listeners))
	wg := completion.NewWaitGroup(ctx)
	var revertFuncs xds.AckingResourceMutatorRevertFuncList

	for _, listener := range resources.Listeners {
		revertFuncs = append(revertFuncs, s.deleteListener(listener.Name, wg, nil))
	}

	start := time.Now()
	log.Debug("DeleteEnvoyResources: Waiting for proxy updates to complete...")
	err := wg.Wait()
	log.Debug("DeleteEnvoyResources: Wait time for proxy updates: ", time.Since(start))

	// revert all changes in case of failure
	if err != nil {
		revertFuncs.Revert(nil)
		log.Debug("DeleteEnvoyResources: Finished reverting failed xDS transactions")
	}
	return err
}
