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
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
)

type FQDNProxyAgentServer struct {
	pb.UnimplementedFQDNProxyAgentServer

	dataSource DNSProxyDataSource
}

func (s *FQDNProxyAgentServer) ProvideMappings(stream pb.FQDNProxyAgent_ProvideMappingsServer) error {
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

func (s *FQDNProxyAgentServer) LookupEndpointByIP(ctx context.Context, IP *pb.FQDN_IP) (*pb.Endpoint, error) {
	ip := net.IP(IP.IP)
	ep, err := s.dataSource.LookupEPByIP(ip)
	if err != nil {
		return &pb.Endpoint{}, err
	}

	return &pb.Endpoint{
		ID:        uint32(ep.ID),
		Identity:  uint32(ep.SecurityIdentity.ID),
		Namespace: ep.K8sNamespace,
		PodName:   ep.K8sPodName,
	}, nil
}

func (s *FQDNProxyAgentServer) LookupSecurityIdentityByIP(ctx context.Context, IP *pb.FQDN_IP) (*pb.Identity, error) {
	ip := net.IP(IP.IP)
	id, exists := s.dataSource.LookupSecIDByIP(ip)

	return &pb.Identity{
		ID:     uint32(id.ID),
		Source: string(id.Source),
		Exists: exists,
	}, nil
}

func (s *FQDNProxyAgentServer) LookupIPsBySecurityIdentity(ctx context.Context, id *pb.Identity) (*pb.IPs, error) {
	ips := s.dataSource.LookupIPsBySecID(identity.NumericIdentity(id.ID))

	//TODO: should this not go to string and back to bytes for transfer?
	ipsForTransfer := make([][]byte, 0, len(ips))

	for i, ip := range ips {
		ipsForTransfer[i] = []byte(net.ParseIP(ip))
	}

	return &pb.IPs{
		IPs: ipsForTransfer,
	}, nil
}

func (s *FQDNProxyAgentServer) NotifyOnDNSMessage(ctx context.Context, notification *pb.DNSNotification) (*pb.Empty, error) {
	//TODO: this should probably be factored out into stream of DNS notifications instead of a rpc call per DNS msg

	endpoint := &endpoint.Endpoint{
		ID: uint16(notification.Endpoint.ID),
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(notification.Endpoint.Identity),
		},
		K8sNamespace: notification.Endpoint.Namespace,
		K8sPodName:   notification.Endpoint.PodName,
	}

	dnsMsg := &dns.Msg{}
	err := dnsMsg.Unpack(notification.Msg)

	if err != nil {
		log.Errorf("Failed to unpack DNS message: %s", err)
		return &pb.Empty{}, err
	}

	return &pb.Empty{}, s.dataSource.NotifyOnDNSMsg(
		notification.Time.AsTime(),
		endpoint,
		notification.EpIPPort,
		notification.ServerAddr,
		dnsMsg,
		notification.Protocol,
		notification.Allowed,
		nil)
}

func newServer(lookupSrc DNSProxyDataSource) *FQDNProxyAgentServer {
	s := &FQDNProxyAgentServer{dataSource: lookupSrc}
	return s
}

func RunServer(port int, lookupSrc DNSProxyDataSource) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterFQDNProxyAgentServer(grpcServer, newServer(lookupSrc))
	grpcServer.Serve(lis)
}

type DNSProxyDataSource interface {
	LookupEPByIP(net.IP) (*endpoint.Endpoint, error)
	LookupSecIDByIP(net.IP) (ipcache.Identity, bool)
	LookupIPsBySecID(identity.NumericIdentity) []string
	NotifyOnDNSMsg(time.Time, *endpoint.Endpoint, string, string, *dns.Msg, string, bool, *dnsproxy.ProxyRequestContext) error
}
