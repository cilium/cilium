package log

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc/grpclog"
)

func init() {
	ctx := WithModule(context.Background(), "grpc")

	// completely replace the grpc logger with the logrus logger.
	grpclog.SetLogger(G(ctx))
}
