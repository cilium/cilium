// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conn

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/timeout"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/pkg/defaults"
	"github.com/cilium/cilium/hubble/pkg/logger"
	"github.com/cilium/cilium/pkg/k8s/portforward"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// GRPCOptionFunc is a function that configures a gRPC dial option.
type GRPCOptionFunc func(vp *viper.Viper) (grpc.DialOption, error)

// GRPCOptionFuncs is a combination of multiple gRPC dial option.
var GRPCOptionFuncs []GRPCOptionFunc

func init() {
	GRPCOptionFuncs = append(
		GRPCOptionFuncs,
		grpcUnaryInterceptors,
		grpcStreamInterceptors,
		grpcOptionTLS,
	)
}

func grpcUnaryInterceptors(vp *viper.Viper) (grpc.DialOption, error) {
	option := grpc.WithChainUnaryInterceptor(
		timeout.UnaryClientInterceptor(vp.GetDuration(config.KeyRequestTimeout)),
		onReceiveHeaderUnaryInterceptor(logger.Logger, logVersionMismatch()),
	)
	return option, nil
}

func grpcStreamInterceptors(vp *viper.Viper) (grpc.DialOption, error) {
	option := grpc.WithChainStreamInterceptor(
		onReceiveHeaderStreamInterceptor(logger.Logger, logVersionMismatch()),
	)
	return option, nil
}

type onReceiveHeader func(log *slog.Logger, header metadata.MD)

// onReceiveHeaderUnaryInterceptor is a gRPC client unary interceptor that retrieves the header
// metadata and execute the provided function.
func onReceiveHeaderUnaryInterceptor(log *slog.Logger, fn onReceiveHeader) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req any, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		var header metadata.MD
		opts = append(opts, grpc.Header(&header))
		if err := invoker(ctx, method, req, reply, cc, opts...); err != nil {
			return err
		}
		fn(log, header)
		return nil
	}
}

// onReceiveHeaderStreamInterceptor is a gRPC client stream interceptor that retrieves the header
// metadata and execute the provided function.
func onReceiveHeaderStreamInterceptor(log *slog.Logger, fn onReceiveHeader) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, err
		}
		// stream.Header() blocks until metadata is ready to read.
		// This could be:
		//  - Forever if no metadata is ever sent.
		//  - After the first read from the stream.
		//  - After an explicit call to SendHeader() server-side.
		// To avoid a possible deadlock, perform header extraction in a goroutine tied to
		// the lifetime of the stream (stream.Header() returns on stream close).
		go func() {
			header, err := stream.Header()
			if err != nil {
				log.Warn("Failed to obtain grpc stream headers in log version mismatch interceptor", logfields.Error, err)
				return
			}
			fn(log, header)
		}()
		return stream, nil
	}
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
		kubeContext := vp.GetString(config.KeyKubeContext)
		kubeconfig := vp.GetString(config.KeyKubeconfig)
		kubeNamespace := vp.GetString(config.KeyKubeNamespace)
		localPort := vp.GetUint16(config.KeyPortForwardPort)

		pf, err := newPortForwarder(kubeContext, kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create k8s port forwader: %w", err)
		}

		// default to first port configured on the service when svcPort is set to 0
		res, err := pf.PortForwardService(ctx, kubeNamespace, "hubble-relay", int32(localPort), 0)
		if err != nil {
			return nil, fmt.Errorf("failed to port forward: %w", err)
		}

		server = fmt.Sprintf("127.0.0.1:%d", res.ForwardedPort.Local)
		logger.Logger.Debug("port-forward to hubble-relay pod running", logfields.Address, server)
	}

	conn, err := New(server)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func newPortForwarder(context, kubeconfig string) (*portforward.PortForwarder, error) {
	restClientGetter := genericclioptions.ConfigFlags{
		Context:    &context,
		KubeConfig: &kubeconfig,
	}
	rawKubeConfigLoader := restClientGetter.ToRawKubeConfigLoader()

	config, err := rawKubeConfigLoader.ClientConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	pf := portforward.NewPortForwarder(clientset, config)
	return pf, nil
}
