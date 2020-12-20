package middleware

import (
	"context"

	"github.com/awslabs/smithy-go/middleware"
)

// RegisterServiceMetadata registers metadata about the service and operation into the middleware context
// so that it is available at runtime for other middleware to introspect.
type RegisterServiceMetadata struct {
	ServiceID     string
	SigningName   string
	Region        string
	OperationName string
}

// ID returns the middleware identifier.
func (s *RegisterServiceMetadata) ID() string {
	return "RegisterServiceMetadata"
}

// HandleInitialize registers service metadata information into the middleware context, allowing for introspection.
func (s RegisterServiceMetadata) HandleInitialize(
	ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
) (out middleware.InitializeOutput, metadata middleware.Metadata, err error) {
	if len(s.ServiceID) > 0 {
		ctx = SetServiceID(ctx, s.ServiceID)
	}
	if len(s.SigningName) > 0 {
		ctx = SetSigningName(ctx, s.SigningName)
	}
	if len(s.Region) > 0 {
		ctx = setRegion(ctx, s.Region)
	}
	if len(s.OperationName) > 0 {
		ctx = setOperationName(ctx, s.OperationName)
	}
	return next.HandleInitialize(ctx, in)
}

// service metadata keys for storing and lookup of runtime stack information.
type (
	serviceIDKey     struct{}
	signingNameKey   struct{}
	signingRegionKey struct{}
	regionKey        struct{}
	operationNameKey struct{}
	partitionIDKey   struct{}
)

// GetServiceID retrieves the service id from the context.
func GetServiceID(ctx context.Context) (v string) {
	v, _ = ctx.Value(serviceIDKey{}).(string)
	return v
}

// GetSigningName retrieves the service signing name from the context.
func GetSigningName(ctx context.Context) (v string) {
	v, _ = ctx.Value(signingNameKey{}).(string)
	return v
}

// GetSigningRegion retrieves the region from the context.
func GetSigningRegion(ctx context.Context) (v string) {
	v, _ = ctx.Value(signingRegionKey{}).(string)
	return v
}

// GetRegion retrieves the endpoint region from the context.
func GetRegion(ctx context.Context) (v string) {
	v, _ = ctx.Value(regionKey{}).(string)
	return v
}

// GetOperationName retrieves the service operation metadata from the context.
func GetOperationName(ctx context.Context) (v string) {
	v, _ = ctx.Value(operationNameKey{}).(string)
	return v
}

// GetPartitionID retrieves the endpoint partition id from the context.
func GetPartitionID(ctx context.Context) string {
	v, _ := ctx.Value(partitionIDKey{}).(string)
	return v
}

// SetSigningName set or modifies the signing name on the context.
func SetSigningName(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, signingNameKey{}, value)
}

// SetSigningRegion sets or modifies the region on the context.
func SetSigningRegion(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, signingRegionKey{}, value)
}

// SetServiceID sets the service id on the context.
func SetServiceID(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, serviceIDKey{}, value)
}

// setRegion sets the endpoint region on the context.
func setRegion(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, regionKey{}, value)
}

// setOperationName sets the service operation on the context.
func setOperationName(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, operationNameKey{}, value)
}

// SetPartitionID sets the partition id of a resolved region on the context
func SetPartitionID(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, partitionIDKey{}, value)
}
