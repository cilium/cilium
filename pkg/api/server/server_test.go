// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server_test

import (
	"context"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"

	"github.com/cilium/cilium/pkg/api/server"
	"github.com/cilium/cilium/pkg/api/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type helloServer struct {
	pb.UnimplementedGreeterServer
}

func (s *helloServer) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	return &pb.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func newHelloServer() types.GRPCServiceOut {
	return types.NewGRPCServiceOut(&pb.Greeter_ServiceDesc, &helloServer{})
}

func TestServer(t *testing.T) {
	tempDir := t.TempDir()
	testSock := path.Join(tempDir, "test.sock")

	h := hive.New(
		server.Cell,
		cell.Provide(newHelloServer),
		cell.Invoke(func(*server.Server) {}),
	)
	hive.AddConfigOverride(
		h,
		func(cfg *server.Config) { cfg.SocketPath = testSock })

	require.NoError(t, h.Start(context.TODO()), "Start")

	conn, err := grpc.Dial("unix://"+testSock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewGreeterClient(conn)

	resp, err := client.SayHello(context.TODO(), &pb.HelloRequest{Name: "test"})
	require.NoError(t, err, "SayHello")
	require.Equal(t, "Hello test", resp.Message)
	require.NoError(t, h.Stop(context.TODO()), "Stop")
}
