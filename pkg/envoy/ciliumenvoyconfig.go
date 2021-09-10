// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"time"

	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/option"
)

// Resources contains all Envoy resources parsed from a CiliumEnvoyConfig CRD
type Resources struct {
	Listeners []*envoy_config_listener.Listener
	Secrets   []*envoy_config_tls.Secret
	Routes    []*envoy_config_route.RouteConfiguration
	Clusters  []*envoy_config_cluster.Cluster
	Endpoints []*envoy_config_endpoint.ClusterLoadAssignment
}

// ParseResources parses all supported Envoy resource types from CiliumEnvoyConfig CRD to Resources type
func ParseResources(namePrefix string, cec *cilium_v2alpha1.CiliumEnvoyConfig) (Resources, error) {
	resources := Resources{}
	for _, r := range cec.Spec.Resources {
		message, err := r.UnmarshalNew()
		if err != nil {
			return Resources{}, err
		}
		typeURL := r.GetTypeUrl()
		switch typeURL {
		case ListenerTypeURL:
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

			// Inject Cilium bpf metadata listener filter, if not already present.
			found := false
			for _, lf := range listener.ListenerFilters {
				if lf.Name == "cilium.bpf_metadata" {
					found = true
				}
			}
			if !found {
				listener.ListenerFilters = append(listener.ListenerFilters, getListenerFilter(false, true))
			}
			// Inject Transparent to work with TPROXY
			listener.Transparent = &wrapperspb.BoolValue{Value: true}
			// Inject listener socket option for Cilium datapath
			listener.SocketOptions = append(listener.SocketOptions, getListenerSocketMarkOption(false))

			// Fill in RDS config source if unset
			for _, fc := range listener.FilterChains {
				for _, filter := range fc.Filters {
					tc := filter.GetTypedConfig()
					if tc == nil || tc.GetTypeUrl() != "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager" {
						continue
					}
					any, err := tc.UnmarshalNew()
					if err != nil {
						continue
					}
					hcmConfig, ok := any.(*envoy_config_http.HttpConnectionManager)
					if !ok {
						continue
					}
					updated := false
					if rds := hcmConfig.GetRds(); rds != nil {
						if rds.ConfigSource == nil {
							rds.ConfigSource = ciliumXDS
							updated = true
						}
					}
					if updated {
						filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: toAny(hcmConfig),
						}
					}
				}
			}
			name := listener.Name
			// listener.Name = namePrefix + "/" + listener.Name // Prepend listener name with k8s resource name
			resources.Listeners = append(resources.Listeners, listener)

			log.Debugf("ParseResources: Parsed listener %s: %v", name, listener)

		case RouteTypeURL:
			route, ok := message.(*envoy_config_route.RouteConfiguration)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Route: %T", message)
			}

			name := route.Name
			// route.Name = namePrefix + "/" + route.Name // Prepend route name with k8s resource name
			resources.Routes = append(resources.Routes, route)

			log.Debugf("ParseResources: Parsed route %s: %v", name, route)

		case ClusterTypeURL:
			cluster, ok := message.(*envoy_config_cluster.Cluster)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Route: %T", message)
			}
			// Fill in EDS config source if unset
			if enum := cluster.GetType(); enum == envoy_config_cluster.Cluster_EDS {
				if cluster.EdsClusterConfig == nil {
					cluster.EdsClusterConfig = &envoy_config_cluster.Cluster_EdsClusterConfig{}
				}
				if cluster.EdsClusterConfig.EdsConfig == nil {
					cluster.EdsClusterConfig.EdsConfig = ciliumXDS
				}
			}

			name := cluster.Name
			// cluster.Name = namePrefix + "/" + cluster.Name // Prepend cluster name with k8s resource name
			resources.Clusters = append(resources.Clusters, cluster)

			log.Debugf("ParseResources: Parsed cluster %s: %v", name, cluster)

		case EndpointTypeURL:
			endpoint, ok := message.(*envoy_config_endpoint.ClusterLoadAssignment)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Route: %T", message)
			}
			resources.Endpoints = append(resources.Endpoints, endpoint)

			log.Debugf("ParseResources: Parsed endpoint: %v", endpoint)

		case SecretTypeURL:
			secret, ok := message.(*envoy_config_tls.Secret)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Secret: %T", message)
			}
			resources.Secrets = append(resources.Secrets, secret)

			log.Debugf("ParseResources: Parsed secret: %v", secret)

		default:
			return Resources{}, fmt.Errorf("Unsupported type: %s", typeURL)
		}
	}
	if len(resources.Listeners) == 0 {
		log.Debugf("ParseResources: No listeners parsed from %v", cec.Spec)
	}
	return resources, nil
}

// UpsertEnvoyResources inserts or updates Envoy resources in 'resources' to the xDS cache,
// from where they will be delivered to Envoy via xDS streaming gRPC.
func (s *XDSServer) UpsertEnvoyResources(ctx context.Context, resources Resources, wait bool) error {
	if option.Config.Debug {
		msg := ""
		sep := ""
		if len(resources.Listeners) > 0 {
			msg += fmt.Sprintf("%d listeners", len(resources.Listeners))
			sep = ", "
		}
		if len(resources.Routes) > 0 {
			msg += fmt.Sprintf("%s%d routes", sep, len(resources.Routes))
			sep = ", "
		}
		if len(resources.Clusters) > 0 {
			msg += fmt.Sprintf("%s%d clusters", sep, len(resources.Clusters))
			sep = ", "
		}
		if len(resources.Endpoints) > 0 {
			msg += fmt.Sprintf("%s%d endpoints", sep, len(resources.Endpoints))
			sep = ", "
		}
		if len(resources.Secrets) > 0 {
			msg += fmt.Sprintf("%s%d secrets", sep, len(resources.Secrets))
		}

		log.Debugf("UpsertEnvoyResources: Upserting %s...", msg)
	}
	var wg *completion.WaitGroup
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	if wait {
		wg = completion.NewWaitGroup(ctx)
	}
	for _, r := range resources.Listeners {
		log.Debugf("Envoy upsertListener %s %v", r.Name, r)
		revertFuncs = append(revertFuncs, s.upsertListener(r.Name, r, wg, nil))
	}
	for _, r := range resources.Routes {
		log.Debugf("Envoy upsertRoute %s %v", r.Name, r)
		revertFuncs = append(revertFuncs, s.upsertRoute(r.Name, r, wg, nil))
	}
	for _, r := range resources.Clusters {
		log.Debugf("Envoy upsertCluster %s %v", r.Name, r)
		revertFuncs = append(revertFuncs, s.upsertCluster(r.Name, r, wg, nil))
	}
	for _, r := range resources.Endpoints {
		log.Debugf("Envoy upsertEndpoint %s %v", r.ClusterName, r)
		revertFuncs = append(revertFuncs, s.upsertEndpoint(r.ClusterName, r, wg, nil))
	}
	for _, r := range resources.Secrets {
		log.Debugf("Envoy upsertSecret %s %v", r.Name, r)
		revertFuncs = append(revertFuncs, s.upsertSecret(r.Name, r, wg, nil))
	}
	if wg != nil {
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
	return nil
}

// UpdateEnvoyResources removes any resources in 'old' that are not
// present in 'new' and then adds or updates all resources in 'new'.
// Envoy does not support changing the listening port of an existing
// listener, so if the port changes we have to delete the old listener
// and then add the new one with the new port number.
func (s *XDSServer) UpdateEnvoyResources(ctx context.Context, old, new Resources, wait bool) error {
	waitForDelete := false
	var wg *completion.WaitGroup
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	if wait {
		wg = completion.NewWaitGroup(ctx)
	}
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

	// Delete old routes not added in 'new'
	var deleteRoutes []*envoy_config_route.RouteConfiguration
	for _, oldRoute := range old.Routes {
		found := false
		for _, newRoute := range new.Routes {
			if newRoute.Name == oldRoute.Name {
				found = true
			}
		}
		if !found {
			deleteRoutes = append(deleteRoutes, oldRoute)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d routes...", len(deleteRoutes), len(new.Routes))
	for _, route := range deleteRoutes {
		revertFuncs = append(revertFuncs, s.deleteRoute(route.Name, wg, nil))
	}

	// Delete old clusters not added in 'new'
	var deleteClusters []*envoy_config_cluster.Cluster
	for _, oldCluster := range old.Clusters {
		found := false
		for _, newCluster := range new.Clusters {
			if newCluster.Name == oldCluster.Name {
				found = true
			}
		}
		if !found {
			deleteClusters = append(deleteClusters, oldCluster)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d clusters...", len(deleteClusters), len(new.Clusters))
	for _, cluster := range deleteClusters {
		revertFuncs = append(revertFuncs, s.deleteCluster(cluster.Name, wg, nil))
	}

	// Delete old endpoints not added in 'new'
	var deleteEndpoints []*envoy_config_endpoint.ClusterLoadAssignment
	for _, oldEndpoint := range old.Endpoints {
		found := false
		for _, newEndpoint := range new.Endpoints {
			if newEndpoint.ClusterName == oldEndpoint.ClusterName {
				found = true
			}
		}
		if !found {
			deleteEndpoints = append(deleteEndpoints, oldEndpoint)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d endpoints...", len(deleteEndpoints), len(new.Endpoints))
	for _, endpoint := range deleteEndpoints {
		revertFuncs = append(revertFuncs, s.deleteEndpoint(endpoint.ClusterName, wg, nil))
	}

	// Delete old secrets not added in 'new'
	var deleteSecrets []*envoy_config_tls.Secret
	for _, oldSecret := range old.Secrets {
		found := false
		for _, newSecret := range new.Secrets {
			if newSecret.Name == oldSecret.Name {
				found = true
			}
		}
		if !found {
			deleteSecrets = append(deleteSecrets, oldSecret)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d secrets...", len(deleteSecrets), len(new.Secrets))
	for _, secret := range deleteSecrets {
		revertFuncs = append(revertFuncs, s.deleteSecret(secret.Name, wg, nil))
	}

	// Have to wait for deletes to complete before adding new listeners if a listener's port number is changed.
	if wg != nil && waitForDelete {
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

	// Add new Secrets
	for _, r := range new.Secrets {
		revertFuncs = append(revertFuncs, s.upsertSecret(r.Name, r, wg, nil))
	}
	// Add new Endpoints
	for _, r := range new.Endpoints {
		revertFuncs = append(revertFuncs, s.upsertEndpoint(r.ClusterName, r, wg, nil))
	}
	// Add new Clusters
	for _, r := range new.Clusters {
		revertFuncs = append(revertFuncs, s.upsertCluster(r.Name, r, wg, nil))
	}
	// Add new Routes
	for _, r := range new.Routes {
		revertFuncs = append(revertFuncs, s.upsertRoute(r.Name, r, wg, nil))
	}
	// Add new Listeners
	for _, r := range new.Listeners {
		revertFuncs = append(revertFuncs, s.upsertListener(r.Name, r, wg, nil))
	}

	if wg != nil {
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
	return nil
}

// DeleteEnvoyResources deletes all Envoy resources in 'resources'.
func (s *XDSServer) DeleteEnvoyResources(ctx context.Context, resources Resources, wait bool) error {
	log.Debugf("UpdateEnvoyResources: Deleting %d listeners, %d routes, %d clusters, %d endpoints, and %d secrets...",
		len(resources.Listeners), len(resources.Routes), len(resources.Clusters), len(resources.Endpoints), len(resources.Secrets))
	var wg *completion.WaitGroup
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	if wait {
		wg = completion.NewWaitGroup(ctx)
	}
	for _, r := range resources.Listeners {
		revertFuncs = append(revertFuncs, s.deleteListener(r.Name, wg, nil))
	}
	for _, r := range resources.Routes {
		revertFuncs = append(revertFuncs, s.deleteRoute(r.Name, wg, nil))
	}
	for _, r := range resources.Clusters {
		revertFuncs = append(revertFuncs, s.deleteCluster(r.Name, wg, nil))
	}
	for _, r := range resources.Endpoints {
		revertFuncs = append(revertFuncs, s.deleteEndpoint(r.ClusterName, wg, nil))
	}
	for _, r := range resources.Secrets {
		revertFuncs = append(revertFuncs, s.deleteSecret(r.Name, wg, nil))
	}

	if wg != nil {
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
	return nil
}
