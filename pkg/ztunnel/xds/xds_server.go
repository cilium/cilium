// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"istio.io/api/security/v1alpha1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	keyPath  = "/etc/ztunnel/private.key"
	certPath = "/etc/ztunnel/root.crt"
)

var _ v1alpha1.IstioCertificateServiceServer = (*Server)(nil)

// Server is a private implemenation of xDS for use with the stand-alone
// zTunnel proxy.
//
// This xDS server will implement a scoped-down xDS API consisting of a
// certificate authority capable of signing CSR(s)s submitted by zTunnel and a
// control plane capable of sending workload and service events to zTunnel.
type Server struct {
	l   net.Listener
	g   *grpc.Server
	log *slog.Logger
	v1alpha1.UnimplementedIstioCertificateServiceServer
}

func NewServer(log *slog.Logger) (*Server, error) {
	x := &Server{
		log: log,
	}
	return x, nil
}

// Serve will create the listening gRPC service and register the required xDS
// endpoints.
//
// If Serve returns without an error the gRPC server is launched within a new
// go routine.
//
// Server.GracefulStop() can be used to kill the running gRPC server.
func (x *Server) Serve() error {
	var err error

	// Note: this initialization code could technically be done during
	// construction, but due to hive/cell needing construction to happen without
	// side effects, do it right before serving.
	creds, err := credentials.NewServerTLSFromFile(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed to create gRPC TLS credentials: %w", err)
	}

	x.g = grpc.NewServer(grpc.Creds(creds))

	v1alpha1.RegisterIstioCertificateServiceServer(x.g, x)

	x.l, err = net.Listen("tcp", "127.0.0.1:15012")
	if err != nil {
		return err
	}

	x.log.Info("zTunnel xDS server started")
	go func() {
		if err = x.g.Serve(x.l); err != nil {
			x.log.Error("gRPC server error", logfields.Error, err)
		}
	}()
	return nil
}

// GracefulStop halts the server gracefully, returning a nil error from the
// underlying gRPC server.
//
// This is useful to kill the server without producing a conflated error that
// would occur when net.Listen() returns an error.
func (x *Server) GracefulStop() {
	x.g.GracefulStop()
}

// CreateCertificate implements the certificate signing process.
func (x *Server) CreateCertificate(ctx context.Context, csr *v1alpha1.IstioCertificateRequest) (*v1alpha1.IstioCertificateResponse, error) {
	return nil, nil
}
