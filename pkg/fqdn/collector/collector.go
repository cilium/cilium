// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package collector

import (
	"fmt"
	"io"
	"net"

	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
)

type FQDNCollectorServer struct {
	pb.UnimplementedFQNDCollectorServer
}

func (s *FQDNCollectorServer) ProvideMappings(stream pb.FQNDCollector_ProvideMappingsServer) error {
	for {
		mapping, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Success{
				Result: true,
			})
		}
		if err != nil {
			return err
		}

		addr := net.IP(mapping.IP)
		log.Debug(fmt.Sprintf("%s -> %s\n", mapping.FQDN, addr.String()))
	}
}

func newServer() *FQDNCollectorServer {
	s := &FQDNCollectorServer{}
	return s
}

func RunServer(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterFQNDCollectorServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}
