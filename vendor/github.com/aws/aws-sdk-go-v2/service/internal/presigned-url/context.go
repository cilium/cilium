package presignedurl

import "context"

// WithIsPresigning adds the isPresigning sentinal value to a context to signal
// that the middleware stack is using the presign flow.
func WithIsPresigning(ctx context.Context) context.Context {
	return context.WithValue(ctx, isPresigning{}, true)
}

// GetIsPresigning returns if the context contains the isPresigning sentinel
// value for presigning flows.
func GetIsPresigning(ctx context.Context) bool {
	v := ctx.Value(isPresigning{})
	if v == nil {
		return false
	}

	return v.(bool)
}

type isPresigning struct{}
