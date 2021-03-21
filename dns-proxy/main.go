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
	"context"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
)

var (
	serverAddr = flag.String("server_addr", "localhost:10000", "The server address in the format of host:port")
)

func main() {
	flag.Parse()
	ctx := context.TODO()

	msgs := make(chan pb.FQDNMapping)

	go startSending(ctx, msgs)

	_, err := StartDNSProxy("", 10001, false, 0, func(addr net.IP, fqdn string) {
		msgs <- pb.FQDNMapping{IP: []byte(addr), FQDN: fqdn}
	})

	if err != nil {
		log.Fatalf("Failed to start dns proxy: %v", err)
	}

	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal
}

func startSending(ctx context.Context, msgs chan pb.FQDNMapping) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())

	opts = append(opts, grpc.WithBlock())

	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewFQNDCollectorClient(conn)

	stream, err := client.ProvideMappings(ctx)
	if err != nil {
		log.Fatalf("failed to create stream: %v", err)
	}
	for {
		msg := <-msgs
		stream.Send(&msg)
	}
}
