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

package cmd

import (
	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"

	"github.com/cilium/cilium/pkg/fqdn/collector"
	"github.com/cilium/cilium/pkg/proxy"
)

func (d *Daemon) bootstrapFqdnCollector() {
	go collector.RunServer(10000, d)

	//TODO: retry that
	conn, err := grpc.Dial("localhost:10002", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	//defer conn.Close()
	proxy.FQDNProxyGRPCClient = pb.NewFQDNProxyClient(conn)
}
