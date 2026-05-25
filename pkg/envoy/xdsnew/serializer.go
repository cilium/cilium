// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

type Resource interface {
	proto.Message
}

func marshal(res Resource) (string, error) {
	opts := protojson.MarshalOptions{UseProtoNames: true, Indent: ""}
	data, err := opts.Marshal(res)
	if err != nil {
		return "", err
	}

	// Since protojson.Marshal does not produce stable output,
	// this is a workaround to produce stable json output.
	// See https://github.com/golang/protobuf/issues/1082
	data2, err := json.Marshal(json.RawMessage(data))
	if err != nil {
		return "", err
	}
	return string(data2), nil
}

func Marshal(resources *xds.Resources) (map[string]string, error) {
	encodedResources := map[string]string{}

	// marshalSorted serializes all resources of a given type in sorted key order
	// to produce a deterministic, complete encoding for versioning.
	marshalSorted := func(typeURL string, keys []string, marshalByKey func(key string) string) {
		slices.SortFunc(keys, cmp.Compare)
		var sb strings.Builder
		for _, k := range keys {
			sb.WriteString(marshalByKey(k))
		}
		if sb.Len() > 0 {
			encodedResources[typeURL] = sb.String()
		}
	}

	endpointKeys := make([]string, 0, len(resources.Endpoints))
	for k := range resources.Endpoints {
		endpointKeys = append(endpointKeys, k)
	}
	marshalSorted(envoy_resource.EndpointType, endpointKeys, func(k string) string {
		s, _ := marshal(resources.Endpoints[k])
		return s
	})

	clusterKeys := make([]string, 0, len(resources.Clusters))
	for k := range resources.Clusters {
		clusterKeys = append(clusterKeys, k)
	}
	marshalSorted(envoy_resource.ClusterType, clusterKeys, func(k string) string {
		s, _ := marshal(resources.Clusters[k])
		return s
	})

	routeKeys := make([]string, 0, len(resources.Routes))
	for k := range resources.Routes {
		routeKeys = append(routeKeys, k)
	}
	marshalSorted(envoy_resource.RouteType, routeKeys, func(k string) string {
		s, _ := marshal(resources.Routes[k])
		return s
	})

	listenerKeys := make([]string, 0, len(resources.Listeners))
	for k := range resources.Listeners {
		listenerKeys = append(listenerKeys, k)
	}
	marshalSorted(envoy_resource.ListenerType, listenerKeys, func(k string) string {
		s, _ := marshal(resources.Listeners[k])
		return s
	})

	secretKeys := make([]string, 0, len(resources.Secrets))
	for k := range resources.Secrets {
		secretKeys = append(secretKeys, k)
	}
	marshalSorted(envoy_resource.SecretType, secretKeys, func(k string) string {
		s, _ := marshal(resources.Secrets[k])
		return s
	})

	npKeys := make([]string, 0, len(resources.NetworkPolicies))
	for k := range resources.NetworkPolicies {
		npKeys = append(npKeys, k)
	}
	marshalSorted(NetworkPolicyTypeURL, npKeys, func(k string) string {
		s, _ := marshal(resources.NetworkPolicies[k])
		return s
	})

	nphKeys := make([]string, 0, len(resources.NetworkPolicyHosts))
	for k := range resources.NetworkPolicyHosts {
		nphKeys = append(nphKeys, k)
	}
	marshalSorted(NetworkPolicyHostsTypeUrl, nphKeys, func(k string) string {
		s, _ := marshal(resources.NetworkPolicyHosts[k])
		return s
	})

	return encodedResources, nil
}

func Unmarshal(encodedResources map[string]string) (xds.Resources, error) {
	resources := xds.Resources{
		Endpoints:          map[string]*endpoint.ClusterLoadAssignment{},
		Clusters:           map[string]*cluster.Cluster{},
		Routes:             map[string]*route.RouteConfiguration{},
		Listeners:          map[string]*listener.Listener{},
		Secrets:            map[string]*secret.Secret{},
		NetworkPolicies:    map[string]*cilium.NetworkPolicy{},
		NetworkPolicyHosts: map[string]*cilium.NetworkPolicyHosts{},
		// PortAllocationCallbacks: nil,
	}
	for resourceType, resource := range encodedResources {
		switch resourceType {
		case envoy_resource.EndpointType:
			unmarshalledEndpoint := &endpoint.ClusterLoadAssignment{}
			err := unmarshal(resource, unmarshalledEndpoint)
			if err != nil {
				return xds.Resources{}, err
			}
			resources.Endpoints[unmarshalledEndpoint.ClusterName] = unmarshalledEndpoint
		case envoy_resource.ClusterType:
			unmarshalledCluster := &cluster.Cluster{}
			err := unmarshal(resource, unmarshalledCluster)
			if err != nil {
				return xds.Resources{}, err
			}
			resources.Clusters[unmarshalledCluster.Name] = unmarshalledCluster
		case envoy_resource.RouteType:
			unmarshalledRoute := &route.RouteConfiguration{}
			err := unmarshal(resource, unmarshalledRoute)
			if err != nil {
				return xds.Resources{}, err
			}
			resources.Routes[unmarshalledRoute.Name] = unmarshalledRoute
		case envoy_resource.ListenerType:
			unmarshalledListener := &listener.Listener{}
			err := unmarshal(resource, unmarshalledListener)
			if err != nil {
				return xds.Resources{}, err
			}
			resources.Listeners[unmarshalledListener.Name] = unmarshalledListener
		case envoy_resource.SecretType:
			unmarshalledSecret := &secret.Secret{}
			err := unmarshal(resource, unmarshalledSecret)
			if err != nil {
				return xds.Resources{}, err
			}
			resources.Secrets[unmarshalledSecret.Name] = unmarshalledSecret
		}
	}
	return resources, nil
}

func unmarshal(str string, res Resource) error {
	if res == nil {
		return fmt.Errorf("resource cannot be nil")
	}

	err := protojson.Unmarshal([]byte(str), res)
	if err != nil {
		return fmt.Errorf("error deserializing resource: '%w'", err)
	}
	return nil
}
