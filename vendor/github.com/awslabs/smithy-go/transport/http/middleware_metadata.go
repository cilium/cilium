package http

import "context"

type (
	hostnameImmutableKey struct{}
	hostPrefixDisableKey struct{}
)

// GetHostnameImmutable retrieves if the endpoint hostname should be considered
// immutable or not.
func GetHostnameImmutable(ctx context.Context) (v bool) {
	v, _ = ctx.Value(hostnameImmutableKey{}).(bool)
	return v
}

// SetHostnameImmutable sets or modifies if the request's endpoint hostname
// should be considered immutable or not.
func SetHostnameImmutable(ctx context.Context, value bool) context.Context {
	return context.WithValue(ctx, hostnameImmutableKey{}, value)
}

// DisableEndpointHostPrefix sets or modifies if the request's endpoint host
// prefixing to be disabled. If value is set to true, endpoint host prefixing
// will be disabled.
func DisableEndpointHostPrefix(ctx context.Context, value bool) context.Context {
	return context.WithValue(ctx, hostPrefixDisableKey{}, value)
}

// IsEndpointHostPrefixDisabled retrieves if the hostname prefixing
//  is disabled.
func IsEndpointHostPrefixDisabled(ctx context.Context) (v bool) {
	v, _ = ctx.Value(hostPrefixDisableKey{}).(bool)
	return v
}
