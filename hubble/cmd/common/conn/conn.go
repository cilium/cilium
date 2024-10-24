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
	"github.com/cilium/cilium/hubble/pkg/logger"
	"github.com/cilium/cilium/pkg/cli/k8s"
)

// GRPCOptionFunc is a function that configures a gRPC dial option.
type GRPCOptionFunc func(vp *viper.Viper) (grpc.DialOption, error)

// GRPCOptionFuncs is a combination of multiple gRPC dial option.
var GRPCOptionFuncs []GRPCOptionFunc

func init() {
	GRPCOptionFuncs = append(
		GRPCOptionFuncs,
		grpcInterceptors,
		grpcOptionTLS,
	)
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
func New(target string) (*grpc.ClientConn, error) {
	t := strings.TrimPrefix(target, defaults.TargetTLSPrefix)
	conn, err := grpc.NewClient(t, grpcDialOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client to '%s': %w", target, err)
	}
	return conn, nil
}

// NewWithFlags creates a new gRPC client connection, optionally port-forwarding to one of the
// hubble-relay pods, using flags to extract the required information.
func NewWithFlags(ctx context.Context, vp *viper.Viper) (*grpc.ClientConn, error) {
	server := vp.GetString(config.KeyServer)

	if vp.GetBool(config.KeyPortForward) {
		k8sContextName := vp.GetString(config.KeyKubeContext)
		k8sKubeconfig := vp.GetString(config.KeyKubeconfig)
		k8sNamespace := vp.GetString(config.KeyKubeNamespace)
		localPort := vp.GetUint16(config.KeyPortForwardPort)

		// ciliumNamespace param is used for initializing helm-specific logic which we don't need here
		k8sClient, err := k8s.NewClient(k8sContextName, k8sKubeconfig, "")
		if err != nil {
			return nil, fmt.Errorf("failed to create k8s client: %w", err)
		}

		// default to first port configured on the service when svcPort is set to 0
		res, err := k8sClient.PortForwardService(ctx, k8sNamespace, "hubble-relay", int32(localPort), 0)
		if err != nil {
			return nil, fmt.Errorf("failed to port forward: %w", err)
		}

		server = fmt.Sprintf("127.0.0.1:%d", res.ForwardedPort.Local)
		logger.Logger.Debug("port-forward to hubble-relay pod running", "addr", server)
	}

	conn, err := New(server)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
