// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultHTTPPort = 8080
	defaultGRPCPort = 9000
	shutdownTimeout = 5 * time.Second

	logKeyError   = "error"
	logKeyHeaders = "headers"
	logKeyHost    = "host"
	logKeyMethod  = "method"
	logKeyPath    = "path"
	logKeyPort    = "port"
)

type server struct {
	authv3.UnimplementedAuthorizationServer
	logger *slog.Logger
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	httpPort := getenvInt("HTTP_PORT", defaultHTTPPort)
	grpcPort := getenvInt("GRPC_PORT", defaultGRPCPort)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", httpPort),
		Handler:           newHTTPMux(logger),
		ReadHeaderTimeout: 5 * time.Second,
	}

	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		logger.Error("failed to listen for gRPC", logKeyError, err)
		os.Exit(1)
	}

	grpcSrv := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcSrv, &server{logger: logger})
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthServer{})

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		logger.Info("starting HTTP auth service", logKeyPort, httpPort)
		err := httpSrv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		logger.Info("starting gRPC auth service", logKeyPort, grpcPort)
		if err := grpcSrv.Serve(grpcLis); err != nil && gctx.Err() == nil {
			return err
		}
		return nil
	})

	<-ctx.Done()
	logger.Info("shutdown requested")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	grpcSrv.GracefulStop()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP shutdown failed", logKeyError, err)
	}

	if err := g.Wait(); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		logger.Error("server exited with error", logKeyError, err)
		os.Exit(1)
	}
}

func newHTTPMux(logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("http ext_authz request",
			logKeyMethod, r.Method,
			logKeyPath, r.URL.Path,
			logKeyHost, r.Host,
			logKeyHeaders, flattenHTTPHeaders(r.Header),
		)
		w.Header().Set("X-Test-Authz", "allowed-http")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("allowed\n"))
	})
	return mux
}

func (s *server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpAttrs := req.GetAttributes().GetRequest().GetHttp()
	s.logger.InfoContext(ctx, "grpc ext_authz request",
		logKeyMethod, httpAttrs.GetMethod(),
		logKeyPath, httpAttrs.GetPath(),
		logKeyHost, httpAttrs.GetHost(),
		logKeyHeaders, flattenHeaderMap(httpAttrs.GetHeaders()),
	)

	return &authv3.CheckResponse{
		Status: status.New(codes.OK, "").Proto(),
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "x-test-authz",
							Value: "allowed-grpc",
						},
					},
				},
				DynamicMetadata: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"result": structpb.NewStringValue("allowed"),
					},
				},
			},
		},
	}, nil
}

type healthServer struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (healthServer) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func (healthServer) Watch(_ *grpc_health_v1.HealthCheckRequest, srv grpc_health_v1.Health_WatchServer) error {
	return srv.Send(&grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING})
}

func getenvInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func flattenHTTPHeaders(headers http.Header) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	parts := make([]string, 0, len(headers))
	for _, key := range keys {
		values := headers[key]
		parts = append(parts, key+"="+strings.Join(values, ","))
	}
	return strings.Join(parts, " ")
}

func flattenHeaderMap(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	parts := make([]string, 0, len(headers))
	for _, key := range keys {
		value := headers[key]
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, " ")
}
