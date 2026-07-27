package types //nolint:revive // var-naming: avoid meaningless package names

import (
	"time"

	"google.golang.org/protobuf/proto"
)

// Resource is the base interface for the xDS payload.
type Resource interface {
	proto.Message
}

// ResourceWithTTL is a Resource with an optional TTL.
type ResourceWithTTL struct {
	Resource Resource
	TTL      *time.Duration
}

// ResourceWithName provides a name for out-of-tree resources.
type ResourceWithName interface {
	proto.Message
	GetName() string
}

// MarshaledResource is an alias for the serialized binary array.
type MarshaledResource = []byte

// SkipFetchError is the error returned when the cache fetch is short
// circuited due to the client's version already being up-to-date.
type SkipFetchError struct{}

// Error satisfies the error interface
func (e SkipFetchError) Error() string {
	return "skip fetch: version up to date"
}

// ResponseType enumeration of supported response types
type ResponseType int

// NOTE: The order of this enum MATTERS!
// https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol#aggregated-discovery-service
// ADS expects things to be returned in a specific order.
// See the following issue for details: https://github.com/envoyproxy/go-control-plane/issues/526
const (
	Cluster ResponseType = iota
	Endpoint
	Listener
	Route
	ScopedRoute
	VirtualHost
	Secret
	Runtime
	ExtensionConfig
	RateLimitConfig
	UnknownType // token to count the total number of supported types
)
