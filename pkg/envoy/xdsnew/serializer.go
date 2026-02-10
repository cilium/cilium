package xdsnew

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/pkg/envoy/xds"
	cilium "github.com/cilium/proxy/go/cilium/api"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

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

	for _, r := range resources.Endpoints {
		endpoints, _ := marshal(r)
		encodedResources[envoy_resource.EndpointType] = endpoints
	}
	for _, r := range resources.Clusters {
		clusters, _ := marshal(r)
		encodedResources[envoy_resource.ClusterType] = clusters
	}
	for _, r := range resources.Routes {
		routes, _ := marshal(r)
		encodedResources[envoy_resource.RouteType] = routes
	}
	for _, r := range resources.Listeners {
		listeners, _ := marshal(r)
		encodedResources[envoy_resource.ListenerType] = listeners
	}
	for _, r := range resources.Secrets {
		secrets, _ := marshal(r)
		encodedResources[envoy_resource.SecretType] = secrets
	}
	for _, r := range resources.NetworkPolicies {
		networkPolicies, _ := marshal(r)
		encodedResources[envoy_resource.ExtensionConfigType] = networkPolicies
	}

	return encodedResources, nil
}

func Unmarshal(encodedResources map[string]string) (xds.Resources, error) {
	resources := xds.Resources{
		Endpoints:       map[string]*endpoint.ClusterLoadAssignment{},
		Clusters:        map[string]*cluster.Cluster{},
		Routes:          map[string]*route.RouteConfiguration{},
		Listeners:       map[string]*listener.Listener{},
		Secrets:         map[string]*secret.Secret{},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{},
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
		return fmt.Errorf("error deserializing resource: '%s'", err)
	}
	return nil
}
