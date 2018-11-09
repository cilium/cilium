package endpoints

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
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

// Partitions returns the partitions that make up the resolver.
func (r *Resolver) Partitions() Partitions {
	return r.partitions.Partitions()
}

// Partitions is a slice of paritions describing regions and endpoints
type Partitions []Partition

// ForRegion returns the first partition which includes the region
// passed in. This includes both known regions and regions which match
// a pattern supported by the partition which may include regions that are
// not explicitly known by the partition. Use the Regions method of the
// returned Partition if explicit support is needed.
func (ps Partitions) ForRegion(id string) (Partition, bool) {
	for _, p := range ps {
		if _, ok := p.p.Regions[id]; ok || p.p.RegionRegex.MatchString(id) {
			return p, true
		}
	}

	return Partition{}, false
}

// ForPartition returns the parition with the matching ID passed in.
func (ps Partitions) ForPartition(id string) (Partition, bool) {
	for _, p := range ps {
		if p.ID() == id {
			return p, true
		}
	}

	return Partition{}, false
}

// A Partition provides the ability to enumerate the partition's regions
// and services.
type Partition struct {
	id string
	p  *partition
}

// ID returns the identifier of the partition.
func (p Partition) ID() string { return p.id }

// Endpoint attempts to resolve the endpoint based on service and region.
// See Options for information on configuring how the endpoint is resolved.
//
// If the service cannot be found in the metadata the endpoint will be resolved
// based on the parition's endpoint pattern, and service endpoint prefix.
//
// When resolving endpoints you can choose to enable StrictMatching. This will
// require the provided service and region to be known by the partition.
// If the endpoint cannot be strictly resolved an error will be returned. This
// mode is useful to ensure the endpoint resolved is valid. Without
// StrictMatching enabled the endpoint returned my look valid but may not work.
// StrictMatching requires the SDK to be updated if you want to take advantage
// of new regions and services expansions.
//
// Errors that can be returned.
//   * UnknownServiceError
//   * UnknownEndpointError
func (p Partition) Endpoint(service, region string, opts ResolveOptions) (aws.Endpoint, error) {
	return p.p.EndpointFor(service, region, opts)
}

// Regions returns a map of Regions indexed by their ID. This is useful for
// enumerating over the regions in a partition.
func (p Partition) Regions() map[string]Region {
	rs := map[string]Region{}
	for id := range p.p.Regions {
		rs[id] = Region{
			id: id,
			p:  p.p,
		}
	}

	return rs
}

// RegionsForService returns the map of regions for the service id specified.
// false is returned if the service is not found in the partition.
func (p Partition) RegionsForService(id string) (map[string]Region, bool) {
	if _, ok := p.p.Services[id]; !ok {
		return nil, false
	}

	s := Service{
		id: id,
		p:  p.p,
	}
	return s.Regions(), true
}

// Services returns a map of Service indexed by their ID. This is useful for
// enumerating over the services in a partition.
func (p Partition) Services() map[string]Service {
	ss := map[string]Service{}
	for id := range p.p.Services {
		ss[id] = Service{
			id: id,
			p:  p.p,
		}
	}

	return ss
}

// Resolver returns an endpoint resolver for the partitions. Use this to satisfy
// the SDK's EndpointResolver.
func (p Partition) Resolver() *Resolver {
	return &Resolver{
		partitions: partitions{*p.p},
	}
}

// A Region provides information about a region, and ability to resolve an
// endpoint from the context of a region, given a service.
type Region struct {
	id, desc string
	p        *partition
}

// ID returns the region's identifier.
func (r Region) ID() string { return r.id }

// Endpoint resolves an endpoint from the context of the region given
// a service. See Partition.EndpointFor for usage and errors that can be returned.
func (r Region) Endpoint(service string, opts ResolveOptions) (aws.Endpoint, error) {
	return r.p.EndpointFor(service, r.id, opts)
}

// Services returns a list of all services that are known to be in this region.
func (r Region) Services() map[string]Service {
	ss := map[string]Service{}
	for id, s := range r.p.Services {
		if _, ok := s.Endpoints[r.id]; ok {
			ss[id] = Service{
				id: id,
				p:  r.p,
			}
		}
	}

	return ss
}

// A Service provides information about a service, and ability to resolve an
// endpoint from the context of a service, given a region.
type Service struct {
	id string
	p  *partition
}

// ID returns the identifier for the service.
func (s Service) ID() string { return s.id }

// Endpoint resolves an endpoint from the context of a service given
// a region. See Partition.EndpointFor for usage and errors that can be returned.
func (s Service) Endpoint(region string, opts ResolveOptions) (aws.Endpoint, error) {
	return s.p.EndpointFor(s.id, region, opts)
}

// Regions returns a map of Regions that the service is present in.
//
// A region is the AWS region the service exists in. Whereas a Endpoint is
// an URL that can be resolved to a instance of a service.
func (s Service) Regions() map[string]Region {
	rs := map[string]Region{}
	for id := range s.p.Services[s.id].Endpoints {
		if _, ok := s.p.Regions[id]; ok {
			rs[id] = Region{
				id: id,
				p:  s.p,
			}
		}
	}

	return rs
}

// Endpoints returns a map of Endpoints indexed by their ID for all known
// endpoints for a service.
//
// A region is the AWS region the service exists in. Whereas a Endpoint is
// an URL that can be resolved to a instance of a service.
func (s Service) Endpoints() map[string]Endpoint {
	es := map[string]Endpoint{}
	for id := range s.p.Services[s.id].Endpoints {
		es[id] = Endpoint{
			id:        id,
			serviceID: s.id,
			p:         s.p,
		}
	}

	return es
}

// A Endpoint provides information about endpoints, and provides the ability
// to resolve that endpoint for the service, and the region the endpoint
// represents.
type Endpoint struct {
	id        string
	serviceID string
	p         *partition
}

// ID returns the identifier for an endpoint.
func (e Endpoint) ID() string { return e.id }

// ServiceID returns the identifier the endpoint belongs to.
func (e Endpoint) ServiceID() string { return e.serviceID }

// Resolve resolves an endpoint from the context of a service and
// region the endpoint represents. See Partition.EndpointFor for usage and
// errors that can be returned.
func (e Endpoint) Resolve(opts ResolveOptions) (aws.Endpoint, error) {
	return e.p.EndpointFor(e.serviceID, e.id, opts)
}

// So that the Error interface type can be included as an anonymous field
// in the requestError struct and not conflict with the error.Error() method.
type awsError awserr.Error

// A UnknownServiceError is returned when the service does not resolve to an
// endpoint. Includes a list of all known services for the partition. Returned
// when a partition does not support the service.
type UnknownServiceError struct {
	awsError
	Partition string
	Service   string
	Known     []string
}

// NewUnknownServiceError builds and returns UnknownServiceError.
func NewUnknownServiceError(p, s string, known []string) UnknownServiceError {
	return UnknownServiceError{
		awsError: awserr.New("UnknownServiceError",
			"could not resolve endpoint for unknown service", nil),
		Partition: p,
		Service:   s,
		Known:     known,
	}
}

// String returns the string representation of the error.
func (e UnknownServiceError) Error() string {
	extra := fmt.Sprintf("partition: %q, service: %q",
		e.Partition, e.Service)
	if len(e.Known) > 0 {
		extra += fmt.Sprintf(", known: %v", e.Known)
	}
	return awserr.SprintError(e.Code(), e.Message(), extra, e.OrigErr())
}

// String returns the string representation of the error.
func (e UnknownServiceError) String() string {
	return e.Error()
}

// A UnknownEndpointError is returned when in StrictMatching mode and the
// service is valid, but the region does not resolve to an endpoint. Includes
// a list of all known endpoints for the service.
type UnknownEndpointError struct {
	awsError
	Partition string
	Service   string
	Region    string
	Known     []string
}

// NewUnknownEndpointError builds and returns UnknownEndpointError.
func NewUnknownEndpointError(p, s, r string, known []string) UnknownEndpointError {
	return UnknownEndpointError{
		awsError: awserr.New("UnknownEndpointError",
			"could not resolve endpoint", nil),
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
	return awserr.SprintError(e.Code(), e.Message(), extra, e.OrigErr())
}

// String returns the string representation of the error.
func (e UnknownEndpointError) String() string {
	return e.Error()
}
