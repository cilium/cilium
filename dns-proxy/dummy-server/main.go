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
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
)

var (
	port = flag.Int("port", 10000, "The server port")
)

type fqdnCollectorServer struct {
	pb.UnimplementedFQNDCollectorServer
}

func (s *fqdnCollectorServer) ProvideMappings(stream pb.FQNDCollector_ProvideMappingsServer) error {
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
		fmt.Printf("%s -> %s\n", mapping.FQDN, addr.String())
	}
}

func newServer() *fqdnCollectorServer {
	s := &fqdnCollectorServer{}
	return s
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterFQNDCollectorServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}
