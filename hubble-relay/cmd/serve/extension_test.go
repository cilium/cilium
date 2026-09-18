// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package serve

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/hubble/build"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/hubble/relay/server"
	"github.com/cilium/cilium/pkg/safeio"
)

// testExtension records each lifecycle stage and returns the configured server
// options, closer, or error so tests can exercise extension orchestration.
var _ Extension = (*testExtension)(nil)

type testExtension struct {
	name          string
	serverOptions []server.Option
	closer        io.Closer
	err           error
	calls         *[]string
	configured    chan<- struct{}
	config        *viper.Viper
	configure     func(*viper.Viper)
}

// Name implements [Extension].
func (e *testExtension) Name() string {
	return e.name
}

// RegisterFlags implements [Extension]. It records flag-registration order and
// adds a flag named after the extension.
func (e *testExtension) RegisterFlags(flags *pflag.FlagSet) {
	*e.calls = append(*e.calls, "flags:"+e.name)
	flags.String(e.name, "", "test extension flag")
}

// Configure implements [Extension]. It records configuration order, captures
// and optionally modifies the shared configuration, and passes the serve
// context to testCloser for cancellation checks.
func (e *testExtension) Configure(ctx context.Context, _ *slog.Logger, vp *viper.Viper) ([]server.Option, io.Closer, error) {
	*e.calls = append(*e.calls, "configure:"+e.name)
	e.config = vp
	if e.configure != nil {
		e.configure(vp)
	}
	if closer, ok := e.closer.(*testCloser); ok {
		closer.ctx = ctx
	}
	if e.configured != nil {
		close(e.configured)
	}
	return e.serverOptions, e.closer, e.err
}

// testCloser records cleanup order and can require the serve context to be
// canceled before cleanup starts.
type testCloser struct {
	name            string
	err             error
	calls           *[]string
	ctx             context.Context
	requireCanceled bool
}

// Close implements [io.Closer]. It records the cleanup call and reports an
// error when its configured cancellation or error condition is not satisfied.
func (c *testCloser) Close() error {
	*c.calls = append(*c.calls, "close:"+c.name)
	if c.requireCanceled && !errors.Is(c.ctx.Err(), context.Canceled) {
		return errors.New("context was not canceled")
	}
	return c.err
}

func TestNewRegistersExtensionFlags(t *testing.T) {
	var calls []string
	extension := &testExtension{name: "downstream-mode", calls: &calls}
	vp := viper.New()

	cmd := New(vp, extension)
	require.NoError(t, cmd.Flags().Set("downstream-mode", "enabled"))

	assert.Equal(t, "enabled", vp.GetString("downstream-mode"))
	assert.Equal(t, []string{"flags:downstream-mode"}, calls)
}

func TestConfigureExtensions(t *testing.T) {
	var calls []string
	first := &testExtension{
		name:          "first",
		serverOptions: []server.Option{server.WithInsecureClient()},
		closer:        &testCloser{name: "first", calls: &calls, requireCanceled: true},
		calls:         &calls,
		configure: func(vp *viper.Viper) {
			assert.Equal(t, "initial", vp.GetString("shared-setting"))
			vp.Set("shared-setting", "first")
		},
	}
	extensions := []Extension{
		first,
		&testExtension{
			name: "second",
			serverOptions: []server.Option{
				server.WithInsecureClient(),
				server.WithInsecureServer(),
			},
			closer: &testCloser{name: "second", calls: &calls, requireCanceled: true},
			calls:  &calls,
			configure: func(vp *viper.Viper) {
				assert.Equal(t, "first", vp.GetString("shared-setting"))
				vp.Set("shared-setting", "second")
			},
		},
	}

	vp := viper.New()
	vp.Set("shared-setting", "initial")
	configured, err := configureExtensions(t.Context(), slog.New(slog.DiscardHandler), vp, extensions)
	require.NoError(t, err)
	assert.Len(t, configured.serverOptions, 3)
	assert.Equal(t, []string{"configure:first", "configure:second"}, calls)
	assert.Same(t, vp, first.config)
	assert.Equal(t, "second", vp.GetString("shared-setting"))

	require.NoError(t, configured.Close())
	assert.Equal(t, []string{
		"configure:first",
		"configure:second",
		"close:second",
		"close:first",
	}, calls)
}

func TestConfigureExtensionsClosesSuccessfulExtensionsOnError(t *testing.T) {
	var calls []string
	extensions := []Extension{
		&testExtension{
			name:   "first",
			closer: &testCloser{name: "first", err: errors.New("close failed"), calls: &calls, requireCanceled: true},
			calls:  &calls,
		},
		&testExtension{
			name:  "second",
			err:   errors.New("configure failed"),
			calls: &calls,
		},
	}

	configured, err := configureExtensions(t.Context(), slog.New(slog.DiscardHandler), viper.New(), extensions)
	require.Error(t, err)
	assert.Nil(t, configured)
	assert.ErrorContains(t, err, `configure serve extension "second": configure failed`)
	assert.ErrorContains(t, err, `close serve extension "first": close failed`)
	assert.Equal(t, []string{"configure:first", "configure:second", "close:first"}, calls)
}

func TestRunServeClosesExtensionsOnStartupError(t *testing.T) {
	var calls []string
	extension := &testExtension{
		name:   "startup-error",
		closer: &testCloser{name: "startup-error", calls: &calls, requireCanceled: true},
		calls:  &calls,
	}
	vp := viper.New()
	New(vp, extension)
	vp.Set(keyGops, false)
	vp.Set(keyTLSClientDisabled, true)
	vp.Set(keyTLSRelayServerCertFile, "/missing/server.crt")
	vp.Set(keyTLSRelayServerKeyFile, "/missing/server.key")

	err := runServe(t.Context(), vp, []Extension{extension})
	require.Error(t, err)
	assert.Equal(t, []string{
		"flags:startup-error",
		"configure:startup-error",
		"close:startup-error",
	}, calls)
}

func TestRunServeExtensionLifecycleAndInterceptorOrder(t *testing.T) {
	// reserveAddress asks the kernel for an unused local address, then releases it
	// so runServe can bind the same address during the test.
	reserveAddress := func() string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		address := listener.Addr().String()
		require.NoError(t, listener.Close())
		return address
	}
	listenAddress := reserveAddress()
	metricsListenAddress := reserveAddress()

	var calls []string
	configured := make(chan struct{})
	extensionHeader := metadata.Pairs(defaults.GRPCMetadataRelayVersionKey, "extension")
	extension := &testExtension{
		name:       "lifecycle",
		closer:     &testCloser{name: "lifecycle", calls: &calls, requireCanceled: true},
		calls:      &calls,
		configured: configured,
		configure: func(vp *viper.Viper) {
			// These replace the unusable values set below. Connecting to both
			// listeners proves Relay reads serve configuration after Configure.
			vp.Set(keyListenAddress, listenAddress)
			vp.Set(keyMetricsListenAddress, metricsListenAddress)
		},
		serverOptions: []server.Option{
			server.WithGRPCUnaryInterceptor(func(ctx context.Context, _ any, _ *grpc.UnaryServerInfo, _ grpc.UnaryHandler) (any, error) {
				grpc.SetHeader(ctx, extensionHeader)
				return nil, status.Error(codes.PermissionDenied, "denied by extension")
			}),
			server.WithGRPCStreamInterceptor(func(_ any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, _ grpc.StreamHandler) error {
				stream.SetHeader(extensionHeader)
				return status.Error(codes.PermissionDenied, "denied by extension")
			}),
		},
	}
	vp := viper.New()
	New(vp, extension)
	vp.Set(keyGops, false)
	vp.Set(keyTLSClientDisabled, true)
	vp.Set(keyTLSServerDisabled, true)
	vp.Set(keyListenAddress, "127.0.0.1:0")
	vp.Set(keyHealthListenAddress, "127.0.0.1:0")
	vp.Set(keyMetricsListenAddress, "")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runServe(ctx, vp, []Extension{extension})
	}()

	select {
	case <-configured:
	case <-time.After(time.Second):
		t.Fatal("extension was not configured")
	}

	conn, err := grpc.NewClient(listenAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	client := healthpb.NewHealthClient(conn)
	rpcCtx, rpcCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer rpcCancel()

	var unaryHeader metadata.MD
	_, err = client.Check(
		rpcCtx,
		&healthpb.HealthCheckRequest{},
		grpc.Header(&unaryHeader),
		grpc.WaitForReady(true),
	)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, []string{"extension", build.RelayVersion.SemVer()}, unaryHeader.Get(defaults.GRPCMetadataRelayVersionKey))

	stream, err := client.Watch(rpcCtx, &healthpb.HealthCheckRequest{}, grpc.WaitForReady(true))
	require.NoError(t, err)
	_, err = stream.Recv()
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	streamHeader, err := stream.Header()
	require.NoError(t, err)
	assert.Equal(t, []string{build.RelayVersion.SemVer(), "extension"}, streamHeader.Get(defaults.GRPCMetadataRelayVersionKey))

	httpClient := &http.Client{Timeout: time.Second}
	require.Eventually(t, func() bool {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+metricsListenAddress+"/metrics", nil)
		if err != nil {
			return false
		}
		response, err := httpClient.Do(request)
		if err != nil {
			return false
		}
		body, err := safeio.ReadAllLimit(response.Body, safeio.MB)
		_ = response.Body.Close()
		if err != nil {
			return false
		}
		metrics := string(body)
		return strings.Contains(metrics, `grpc_server_handled_total{grpc_code="PermissionDenied",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 1`) &&
			strings.Contains(metrics, `grpc_server_handled_total{grpc_code="PermissionDenied",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 1`)
	}, 5*time.Second, 10*time.Millisecond)

	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve command did not stop")
	}
	assert.Equal(t, []string{
		"flags:lifecycle",
		"configure:lifecycle",
		"close:lifecycle",
	}, calls)
}
