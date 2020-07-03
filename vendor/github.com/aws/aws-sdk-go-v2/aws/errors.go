package aws

// MissingRegionError is an error that is returned if region configuration is not found.
type MissingRegionError struct{}

func (*MissingRegionError) Error() string {
	return "could not find region configuration"
}

// MissingEndpointError is an error that is returned if an endpoint cannot be resolved for a service.
type MissingEndpointError struct{}

func (*MissingEndpointError) Error() string {
	return "'Endpoint' configuration is required for this service"
}
