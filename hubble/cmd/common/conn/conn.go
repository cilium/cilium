// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/timeout"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/k8s"
	"github.com/cilium/cilium/hubble/pkg/defaults"
	"github.com/cilium/cilium/hubble/pkg/logger"
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

// NewWithFlags creates a new gRPC client connection, optionally with kubectl port-forwarding to the
// hubble-relay service, using flags to extract the required information.
func NewWithFlags(ctx context.Context, vp *viper.Viper) (conn *grpc.ClientConn, cleanup func() error, err error) {
	var cleanupFns []func() error
	server := vp.GetString(config.KeyServer)
	dialTimeout := vp.GetDuration(config.KeyTimeout)

	// if auto port forward is enabled, query the k8s api for the hubble-relay svc port
	// and launch a kubectl port-forward process
	if vp.GetBool(config.KeyAutoPortForward) {
		// inspired by: cilium-cli/hubble/relay.go:RelayPortForwardCommand()
		// TODO: should we try to consolidate with cilium-cli ?
		// TODO: second iteration: replace with native port-forward using k8s client (ProxyTCP())
		k8sContextName := vp.GetString(config.KeyK8sContextName)
		k8sKubeconfig := vp.GetString(config.KeyK8sKubeconfig)
		k8sNamespace := vp.GetString(config.KeyK8sNamespace)
		localPort := vp.GetUint16(config.KeyPortForward)

		k8sClient, err := k8s.NewClient(k8sContextName, k8sKubeconfig)
		if err != nil {
			return nil, nil, err
		}

		logger.Logger.Debug("Querying kubernetes API for hubble-relay service")
		relaySvc, err := k8sClient.GetService(ctx, k8sNamespace, "hubble-relay", metav1.GetOptions{})
		if err != nil {
			return nil, nil, err
		}

		// TODO: re-using grpc dial timeout, should we hardcode this or have another flag?
		portForwardAddr, portForwardCleanup, err := kubectlPortForward(ctx, k8sNamespace, k8sContextName, dialTimeout, int(localPort), int(relaySvc.Spec.Ports[0].Port))
		if err != nil {
			return nil, nil, err
		}
		server = portForwardAddr
		cleanupFns = append(cleanupFns, portForwardCleanup)
	}

	conn, err = New(ctx, server, dialTimeout)
	if err != nil {
		return nil, nil, err
	}
	cleanupFns = append(cleanupFns, conn.Close)

	cleanup = func() error {
		var err error
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			err = errors.Join(err, cleanupFns[i]())
		}
		return err
	}
	return conn, cleanup, nil
}

func kubectlPortForward(ctx context.Context, namespace, contextName string, dialTimeout time.Duration, local, remote int) (addr string, cleanup func() error, err error) {
	localAddr := fmt.Sprintf("127.0.0.1:%d", local)

	logger.Logger.Debug("Checking if port is already opened for port forwarding", "addr", localAddr)
	if err := doTCPProbe(localAddr, dialTimeout); err == nil {
		return "", nil, fmt.Errorf("cannot setup port-forwarding: already listening: %s", localAddr)
	}

	args := []string{
		"port-forward",
		"-n", namespace,
		"svc/hubble-relay",
		"--address", "127.0.0.1",
		fmt.Sprintf("%d:%d", local, remote)}
	if contextName != "" {
		args = append([]string{"--context", contextName}, args...)
	}

	logger.Logger.Debug("Launching kubectl command", "args", args)
	// TODO: is there a cleaner/more succint way to handle this?
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	cleanup = func() error {
		logger.Logger.Debug("Cleaning up kubectl command", "args", args)
		cancel()
		return cmd.Wait()
	}
	defer func() {
		if err != nil {
			cleanup()
		}
	}()
	if err := cmd.Start(); err != nil {
		return "", nil, err
	}

	maxRetries := 10
	retryInterval := time.Second
	retries := 0
	for {
		if retries > maxRetries {
			return "", nil, fmt.Errorf("cannot setup port-forwarding: max retry reached (%d)", maxRetries)
		}
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(retryInterval):
		}
		retries += 1

		// TODO: we should race both the probe and the process state to allow failing early
		if err := doTCPProbe(localAddr, dialTimeout); err == nil {
			logger.Logger.Debug("Port forwarding established")
			break
		}
		logger.Logger.Debug("Cannot setup port-forwarding: dial failed: will retry",
			"addr", localAddr, "retries", retries, "maxRetries", maxRetries)
	}

	return localAddr, cleanup, nil
}

func doTCPProbe(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	if err := conn.Close(); err != nil {
		logger.Logger.Error("Unexpected error closing TCP socket", "addr", addr, "err", err)
	}
	return nil
}
