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
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"

	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/source"
)

var (
	serverAddr = flag.String("server_addr", "localhost:10000", "The server address in the format of host:port")
	client     pb.FQDNProxyAgentClient
)

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*serverAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client = pb.NewFQDNProxyAgentClient(conn)

	//ctx := context.TODO()

	//msgs := make(chan pb.FQDNMapping)

	//go startSending(ctx, msgs)

	_, err = dnsproxy.StartDNSProxy("", 10001, false, 0, LookupEndpointIDByIP, LookupSecIDByIP, LookupIPsBySecID, NotifyOnDNSMsg)
	//_, err := dnsproxy.StartDNSProxy("", 10001, false, 0, func(addr net.IP, fqdn string) {
	//	msgs <- pb.FQDNMapping{IP: []byte(addr), FQDN: fqdn}
	//})

	if err != nil {
		log.Fatalf("Failed to start dns proxy: %v", err)
	}

	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal
}

// LookupEndpointIDByIP wraps logic to lookup an endpoint with any backend.
func LookupEndpointIDByIP(ip net.IP) (*endpoint.Endpoint, error) {
	ep, err := client.LookupEndpointByIP(context.TODO(), &pb.FQDN_IP{IP: ip})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not lookup endpoint for ip %s: %v", ip, err))
	}

	return &endpoint.Endpoint{
		ID: uint16(ep.ID),
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(ep.Identity),
		},
		K8sNamespace: ep.Namespace,
		K8sPodName:   ep.PodName,
	}, nil
}

// LookupSecIDByIP wraps logic to lookup an IP's security ID from the
// ipcache.
func LookupSecIDByIP(ip net.IP) (secID ipcache.Identity, exists bool) {
	id, err := client.LookupSecurityIdentityByIP(context.TODO(), &pb.FQDN_IP{IP: ip})
	if err != nil || id == nil {
		log.Errorf("could not lookup security identity for ip %s: %v", ip, err)
		return ipcache.Identity{}, false
	}

	return ipcache.Identity{
		ID:     identity.NumericIdentity(id.ID),
		Source: source.Source(id.Source),
	}, id.Exists
}

// LookupIPsBySecID wraps logic to lookup an IPs by security ID from the
// ipcache.
func LookupIPsBySecID(nid identity.NumericIdentity) []string {
	return []string{}
}

// NotifyOnDNSMsghandles propagating DNS response data
func NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	return errors.New("not implemented")
}

//func startSending(ctx context.Context, msgs chan pb.FQDNMapping) {
//	var opts []grpc.DialOption
//	opts = append(opts, grpc.WithInsecure())
//
//	opts = append(opts, grpc.WithBlock())
//
//	conn, err := grpc.Dial(*serverAddr, opts...)
//	if err != nil {
//		log.Fatalf("fail to dial: %v", err)
//	}
//	defer conn.Close()
//
//	client := pb.NewFQNDProxyAgentClient(conn)
//
//	stream, err := client.ProvideMappings(ctx)
//	if err != nil {
//		log.Fatalf("failed to create stream: %v", err)
//	}
//	for {
//		msg := <-msgs
//		stream.Send(&msg)
//	}
//}
