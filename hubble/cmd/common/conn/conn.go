// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conn

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/timeout"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/pkg/defaults"
	"github.com/cilium/cilium/hubble/pkg/logger"
	hubbledefaults "github.com/cilium/cilium/pkg/hubble/defaults"
	relaydefaults "github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/k8s/portforward"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// GRPCOptionFunc is a function that configures a gRPC dial option.
type GRPCOptionFunc func(vp *viper.Viper) (grpc.DialOption, error)

// GRPCOptionFuncs is a combination of multiple gRPC dial option.
var GRPCOptionFuncs []GRPCOptionFunc

func init() {
	GRPCOptionFuncs = append(GRPCOptionFuncs,
		grpcUnaryInterceptors,
		grpcStreamInterceptors,
		grpcOptionTLS,
	)
}

func grpcUnaryInterceptors(vp *viper.Viper) (grpc.DialOption, error) {
	option := grpc.WithChainUnaryInterceptor(
		timeout.UnaryClientInterceptor(vp.GetDuration(config.KeyRequestTimeout)),
		logging.UnaryClientInterceptor(interceptorLogger(), logging.WithFieldsFromContext(logVersions)),
		extractVersionsUnaryInterceptor(),
	)
	return option, nil
}

func grpcStreamInterceptors(vp *viper.Viper) (grpc.DialOption, error) {
	option := grpc.WithChainStreamInterceptor(
		logging.StreamClientInterceptor(interceptorLogger(), logging.WithFieldsFromContext(logVersions)),
		// extractVersionsStreamInterceptor(),
	)
	return option, nil
}

// interceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func interceptorLogger() logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		logger.Logger.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func extractVersionsUnaryInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req any, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		// retrieve headers
		var header metadata.MD
		opts = append(opts, grpc.Header(&header))
		ctx = context.WithValue(ctx, relaydefaults.GRPCMetadataRelayVersionKey, "testing")
		if err := invoker(ctx, method, req, reply, cc, opts...); err != nil {
			return err
		}
		ctx = extractVersionsIntoCtx(ctx, header)
		return nil
	}
}

func extractVersionsStreamInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, err
		}
		// blocks until first response is received or sendHeader is called from server
		header, _ := stream.Header()
		ctx = extractVersionsIntoCtx(ctx, header)
		return stream, nil
	}
}

// extractVersionsIntoCtx extract version metadata from headers and store them in context.
func extractVersionsIntoCtx(ctx context.Context, header metadata.MD) context.Context {
	// We only see relay-version here with current setup.
	// I think this is because we don't propagate headers obtained from peers
	// and it makes sense because when you collect data from multiple peers
	// how do you forward the server-version? For now seems like we can rely on
	// relay-version because hopefully it matches cilium version?
	logger.Logger.Debug("print headers", "headers", fmt.Sprintf("%+v", header))

	if ctx == nil {
		ctx = context.Background()
	}
	if values := header.Get(hubbledefaults.GRPCMetadataServerVersionKey); len(values) > 0 {
		ctx = context.WithValue(ctx, hubbledefaults.GRPCMetadataServerVersionKey, values[0])
	}
	if values := header.Get(relaydefaults.GRPCMetadataRelayVersionKey); len(values) > 0 {
		ctx = context.WithValue(ctx, relaydefaults.GRPCMetadataRelayVersionKey, values[0])
	}
	return ctx
}

// logVersions extracts version metadata from context for logging.
func logVersions(ctx context.Context) logging.Fields {
	var fields logging.Fields
	if value, ok := ctx.Value(hubbledefaults.GRPCMetadataServerVersionKey).(string); ok {
		fields = append(fields, logfields.ServerVersion, value)
	}
	if value, ok := ctx.Value(relaydefaults.GRPCMetadataRelayVersionKey).(string); ok {
		fields = append(fields, logfields.RelayVersion, value)
	}

	logger.Logger.Debug("print ctx", "ctx", ctx)
	logger.Logger.Debug("print fields", "fields", fmt.Sprintf("%+v", fields))
	logger.Logger.Debug("ctx relay-version", "value", ctx.Value(relaydefaults.GRPCMetadataRelayVersionKey))

	return fields
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
