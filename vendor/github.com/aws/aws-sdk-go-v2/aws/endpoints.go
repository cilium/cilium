package aws

// EndpointResolver resolves an endpoint for a service endpoint id and region.
type EndpointResolver interface {
	ResolveEndpoint(service, region string) (Endpoint, error)
}

// EndpointResolverFunc is a helper utility that wraps a function so it satisfies the
// Resolver interface. This is useful when you want to add additional endpoint
// resolving logic, or stub out specific endpoints with custom values.
type EndpointResolverFunc func(service, region string) (Endpoint, error)

// ResolveEndpoint calls EndpointResolverFunc returning the endpoint, or error.
func (fn EndpointResolverFunc) ResolveEndpoint(service, region string) (Endpoint, error) {
	return fn(service, region)
}

// ResolveWithEndpoint allows a static Resolved Endpoint to be used as an endpoint resolver
type ResolveWithEndpoint Endpoint

// ResolveWithEndpointURL allows a static URL to be used as a endpoint resolver.
func ResolveWithEndpointURL(url string) ResolveWithEndpoint {
	return ResolveWithEndpoint(Endpoint{URL: url})
}

// ResolveEndpoint returns the static endpoint.
func (v ResolveWithEndpoint) ResolveEndpoint(service, region string) (Endpoint, error) {
	e := Endpoint(v)
	e.SigningRegion = region
	return e, nil
}

// Endpoint represents the endpoint a service client should make requests to.
type Endpoint struct {
	// The URL of the endpoint.
	URL string

	// The endpoint partition
	PartitionID string

	// The service name that should be used for signing the requests to the
	// endpoint.
	SigningName string

	// The region that should be used for signing the request to the endpoint.
	SigningRegion string

	// States that the signing name for this endpoint was derived from metadata
	// passed in, but was not explicitly modeled.
	SigningNameDerived bool

	// The signing method that should be used for signign the requests to the
	// endpoint.
	SigningMethod string
}
