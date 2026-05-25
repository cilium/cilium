package stream

import (
	"google.golang.org/grpc"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

// Generic RPC stream for state of the world.
type Stream interface {
	grpc.ServerStream

	Send(*discovery.DiscoveryResponse) error
	Recv() (*discovery.DiscoveryRequest, error)
}

// Generic RPC Stream for the delta based xDS protocol.
type DeltaStream interface {
	grpc.ServerStream

	Send(*discovery.DeltaDiscoveryResponse) error
	Recv() (*discovery.DeltaDiscoveryRequest, error)
}
