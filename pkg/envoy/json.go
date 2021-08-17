// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
)

// Resources
type Resources struct {
	Listeners []*envoy_config_listener.Listener
}

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

func (s *XDSServer) UpsertEnvoyResources(ctx context.Context, resources Resources) error {
	log.Debugf("UpsertEnvoyResources: Upserting %d listeners...", len(resources.Listeners))
	wg := completion.NewWaitGroup(ctx)
	for i := range resources.Listeners {
		s.upsertListener(resources.Listeners[i].Name, resources.Listeners[i], wg)
	}

	start := time.Now()
	log.Debug("UpsertEnvoyResources: Waiting for proxy updates to complete...")
	err := wg.Wait()
	log.Debug("UpsertEnvoyResources: Wait time for proxy updates: ", time.Since(start))
	return err
}

func (s *XDSServer) UpdateEnvoyResources(ctx context.Context, old, new Resources) error {
	waitForDelete := false
	wg := completion.NewWaitGroup(ctx)
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
		s.deleteListener(listener.Name, wg)
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
		s.upsertListener(new.Listeners[i].Name, new.Listeners[i], wg)
	}

	start := time.Now()
	log.Debug("UpdateEnvoyResources: Waiting for proxy updates to complete...")
	err := wg.Wait()
	log.Debug("UpdateEnvoyResources: Wait time for proxy updates: ", time.Since(start))
	return err
}

func (s *XDSServer) DeleteEnvoyResources(ctx context.Context, resources Resources) error {
	log.Debugf("UpdateEnvoyResources: Deleting %d listeners...", len(resources.Listeners))
	wg := completion.NewWaitGroup(ctx)

	for _, listener := range resources.Listeners {
		s.deleteListener(listener.Name, wg)
	}

	start := time.Now()
	log.Debug("DeleteEnvoyResources: Waiting for proxy updates to complete...")
	err := wg.Wait()
	log.Debug("DeleteEnvoyResources: Wait time for proxy updates: ", time.Since(start))
	return err
}
