// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

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

type serializedResource struct {
	Name     string          `json:"name"`
	Resource json.RawMessage `json:"resource"`
}

func resourceKeys[T any](resources map[string]T) []string {
	keys := make([]string, 0, len(resources))
	for k := range resources {
		keys = append(keys, k)
	}
	return keys
}

func Marshal(resources *xds.Resources) (map[string]string, error) {
	encodedResources := map[string]string{}

	// marshalSorted serializes all resources of a given type in sorted key order
	// to produce a deterministic, complete encoding for versioning.
	marshalSorted := func(typeURL string, keys []string, marshalByKey func(key string) (string, error)) error {
		if len(keys) == 0 {
			return nil
		}

		slices.SortFunc(keys, cmp.Compare)
		serializedResources := make([]serializedResource, 0, len(keys))
		for _, k := range keys {
			marshaledResource, err := marshalByKey(k)
			if err != nil {
				return err
			}
			serializedResources = append(serializedResources, serializedResource{
				Name:     k,
				Resource: json.RawMessage(marshaledResource),
			})
		}

		data, err := json.Marshal(serializedResources)
		if err != nil {
			return err
		}
		encodedResources[typeURL] = string(data)
		return nil
	}

	if err := marshalSorted(envoy_resource.EndpointType, resourceKeys(resources.Endpoints), func(k string) (string, error) {
		return marshal(resources.Endpoints[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.ClusterType, resourceKeys(resources.Clusters), func(k string) (string, error) {
		return marshal(resources.Clusters[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.RouteType, resourceKeys(resources.Routes), func(k string) (string, error) {
		return marshal(resources.Routes[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.ListenerType, resourceKeys(resources.Listeners), func(k string) (string, error) {
		return marshal(resources.Listeners[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.SecretType, resourceKeys(resources.Secrets), func(k string) (string, error) {
		return marshal(resources.Secrets[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(NetworkPolicyTypeURL, resourceKeys(resources.NetworkPolicies), func(k string) (string, error) {
		return marshal(resources.NetworkPolicies[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(NetworkPolicyHostsTypeURL, resourceKeys(resources.NetworkPolicyHosts), func(k string) (string, error) {
		return marshal(resources.NetworkPolicyHosts[k])
	}); err != nil {
		return nil, err
	}

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
	for resourceType, resourceList := range encodedResources {
		switch resourceType {
		case envoy_resource.EndpointType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledEndpoint := &endpoint.ClusterLoadAssignment{}
				if err := unmarshal(resource, unmarshalledEndpoint); err != nil {
					return err
				}
				resources.Endpoints[name] = unmarshalledEndpoint
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case envoy_resource.ClusterType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledCluster := &cluster.Cluster{}
				if err := unmarshal(resource, unmarshalledCluster); err != nil {
					return err
				}
				resources.Clusters[name] = unmarshalledCluster
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case envoy_resource.RouteType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledRoute := &route.RouteConfiguration{}
				if err := unmarshal(resource, unmarshalledRoute); err != nil {
					return err
				}
				resources.Routes[name] = unmarshalledRoute
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case envoy_resource.ListenerType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledListener := &listener.Listener{}
				if err := unmarshal(resource, unmarshalledListener); err != nil {
					return err
				}
				resources.Listeners[name] = unmarshalledListener
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case envoy_resource.SecretType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledSecret := &secret.Secret{}
				if err := unmarshal(resource, unmarshalledSecret); err != nil {
					return err
				}
				resources.Secrets[name] = unmarshalledSecret
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case NetworkPolicyTypeURL:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledNetworkPolicy := &cilium.NetworkPolicy{}
				if err := unmarshal(resource, unmarshalledNetworkPolicy); err != nil {
					return err
				}
				resources.NetworkPolicies[name] = unmarshalledNetworkPolicy
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case NetworkPolicyHostsTypeURL:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledNetworkPolicyHosts := &cilium.NetworkPolicyHosts{}
				if err := unmarshal(resource, unmarshalledNetworkPolicyHosts); err != nil {
					return err
				}
				resources.NetworkPolicyHosts[name] = unmarshalledNetworkPolicyHosts
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		}
	}
	return resources, nil
}

func unmarshalEach(str string, decode func(name string, resource json.RawMessage) error) error {
	var serializedResources []serializedResource
	if err := json.Unmarshal([]byte(str), &serializedResources); err != nil {
		return fmt.Errorf("error deserializing resources: %w", err)
	}

	for _, serializedResource := range serializedResources {
		if len(serializedResource.Resource) == 0 {
			return fmt.Errorf("resource %q cannot be empty", serializedResource.Name)
		}
		if err := decode(serializedResource.Name, serializedResource.Resource); err != nil {
			return err
		}
	}
	return nil
}

func unmarshal(data []byte, res Resource) error {
	if res == nil {
		return fmt.Errorf("resource cannot be nil")
	}

	err := protojson.Unmarshal(data, res)
	if err != nil {
		return fmt.Errorf("error deserializing resource: %w", err)
	}
	return nil
}
