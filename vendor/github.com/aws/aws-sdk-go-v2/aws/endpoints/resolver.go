package endpoints

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// ResolveOptions provide the configuration needed to direct how the
// endpoints will be resolved.
type ResolveOptions struct {
	// DisableSSL forces the endpoint to be resolved as HTTP.
	// instead of HTTPS if the service supports it.
	DisableSSL bool

	// Sets the resolver to resolve the endpoint as a dualstack endpoint
	// for the service. If dualstack support for a service is not known and
	// StrictMatching is not enabled a dualstack endpoint for the service will
	// be returned. This endpoint may not be valid. If StrictMatching is
	// enabled only services that are known to support dualstack will return
	// dualstack endpoints.
	UseDualStack bool

	// Enables strict matching of services and regions resolved endpoints.
	// If the partition doesn't enumerate the exact service and region an
	// error will be returned. This option will prevent returning endpoints
	// that look valid, but may not resolve to any real endpoint.
	StrictMatching bool
}

// A Resolver provides endpoint resolution based on modeled endpoint data.
type Resolver struct {
	ResolveOptions

	partitions partitions
}

// ResolveEndpoint attempts to resolve an endpoint againsted the modeled endpoint
// data. If an endpoint is found it will be returned. An error will be returned
// otherwise.
//
// Searches through the partitions in the order they are defined.
func (r *Resolver) ResolveEndpoint(service, region string) (aws.Endpoint, error) {
	return r.partitions.EndpointFor(service, region, r.ResolveOptions)
}

// A UnknownServiceError is returned when the service does not resolve to an
// endpoint. Includes a list of all known services for the partition. Returned
// when a partition does not support the service.
type UnknownServiceError struct {
	Partition string
	Service   string
	Known     []string
}

// NewUnknownServiceError builds and returns UnknownServiceError.
func NewUnknownServiceError(p, s string, known []string) UnknownServiceError {
	return UnknownServiceError{
		Partition: p,
		Service:   s,
		Known:     known,
	}
}

// String returns the string representation of the error.
func (e UnknownServiceError) Error() string {
	extra := fmt.Sprintf("partition: %q, service: %q", e.Partition, e.Service)
	if len(e.Known) > 0 {
		extra += fmt.Sprintf(", known: %v", e.Known)
	}
	return "unknown service, could not resolve endpoint, " + extra
}

// A UnknownEndpointError is returned when in StrictMatching mode and the
// service is valid, but the region does not resolve to an endpoint. Includes
// a list of all known endpoints for the service.
type UnknownEndpointError struct {
	Partition string
	Service   string
	Region    string
	Known     []string
}

// NewUnknownEndpointError builds and returns UnknownEndpointError.
func NewUnknownEndpointError(p, s, r string, known []string) UnknownEndpointError {
	return UnknownEndpointError{
		Partition: p,
		Service:   s,
		Region:    r,
		Known:     known,
	}
}

// String returns the string representation of the error.
func (e UnknownEndpointError) Error() string {
	extra := fmt.Sprintf("partition: %q, service: %q, region: %q",
		e.Partition, e.Service, e.Region)
	if len(e.Known) > 0 {
		extra += fmt.Sprintf(", known: %v", e.Known)
	}
	return "unknown endpoint, could not resolve endpoint, " + extra
}
