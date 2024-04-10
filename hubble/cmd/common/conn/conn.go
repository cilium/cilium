// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conn

import (
	"context"
	"fmt"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/timeout"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/pkg/defaults"
	"github.com/cilium/cilium/pkg/time"
)

// GRPCOptionFunc is a function that configures a gRPC dial option.
type GRPCOptionFunc func(vp *viper.Viper) (grpc.DialOption, error)

// GRPCOptionFuncs is a combination of multiple gRPC dial option.
var GRPCOptionFuncs []GRPCOptionFunc

func init() {
	GRPCOptionFuncs = append(
		GRPCOptionFuncs,
		grpcOptionBlock,
		grpcOptionFailOnNonTempDialError,
		grpcOptionConnError,
		grpcInterceptors,
		grpcOptionTLS,
	)
}

func grpcOptionBlock(_ *viper.Viper) (grpc.DialOption, error) {
	return grpc.WithBlock(), nil
}

func grpcOptionFailOnNonTempDialError(_ *viper.Viper) (grpc.DialOption, error) {
	return grpc.FailOnNonTempDialError(true), nil
}

func grpcOptionConnError(_ *viper.Viper) (grpc.DialOption, error) {
	return grpc.WithReturnConnectionError(), nil
}

func grpcInterceptors(vp *viper.Viper) (grpc.DialOption, error) {
	return grpc.WithUnaryInterceptor(timeout.UnaryClientInterceptor(vp.GetDuration(config.KeyRequestTimeout))), nil
}

var grpcDialOptions []grpc.DialOption

// Init initializes common connection options. It MUST be called prior to any
// other package functions.
func Init(vp *viper.Viper) error {
	for _, fn := range GRPCOptionFuncs {
		dialOpt, err := fn(vp)
		if err != nil {
			return err
		}
		grpcDialOptions = append(grpcDialOptions, dialOpt)
	}
	return nil
}

// New creates a new gRPC client connection to the target.
func New(ctx context.Context, target string, dialTimeout time.Duration) (*grpc.ClientConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	t := strings.TrimPrefix(target, defaults.TargetTLSPrefix)
	conn, err := grpc.DialContext(dialCtx, t, grpcDialOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to '%s': %w", target, err)
	}
	return conn, nil
}
