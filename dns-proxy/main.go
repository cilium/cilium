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
	"regexp"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"

	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
)

var (
	agentAddr = flag.String("server_addr", "localhost:10000", "The server address in the format of host:port")
	client    pb.FQDNProxyAgentClient
)

func main() {
	flag.Parse()
	log.Info("started dns proxy")
	conn, err := grpc.Dial(*agentAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client = pb.NewFQDNProxyAgentClient(conn)
	log.Info("grpc client")

	proxy, err := dnsproxy.StartDNSProxy("", 10001, false, 0, LookupEndpointIDByIP, LookupSecIDByIP, LookupIPsBySecID, NotifyOnDNSMsg)

	if err != nil {
		log.Fatalf("Failed to start dns proxy: %v", err)
	}
	log.Info("started dns proxy")

	//TODO: get this from config
	proxy.SetRejectReply("reject reply")

	go RunServer(10002, proxy)

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
	ips, err := client.LookupIPsBySecurityIdentity(context.TODO(), &pb.Identity{ID: uint32(nid)})
	if err != nil {
		log.Errorf("could not lookup ips for id %v: %v", nid, err)
		return nil
	}

	result := make([]string, 0, len(ips.IPs))
	for _, ip := range ips.IPs {
		result = append(result, net.IP(ip).String())
	}
	return result
}

// NotifyOnDNSMsghandles propagating DNS response data
func NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, agentAddr string, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	//TODO: retain stat somehow?

	endpoint := &pb.Endpoint{
		ID:        uint32(ep.ID),
		Identity:  uint32(ep.SecurityIdentity.ID),
		Namespace: ep.K8sNamespace,
		PodName:   ep.K8sPodName,
	}

	dnsMsg, err := msg.Pack()
	if err != nil {
		log.Errorf("Could not pack dns msg: %s", err)
		return err
	}

	_, err = client.NotifyOnDNSMessage(context.TODO(), &pb.DNSNotification{
		Time:       timestamppb.New(lookupTime),
		Endpoint:   endpoint,
		EpIPPort:   epIPPort,
		ServerAddr: agentAddr,
		Msg:        dnsMsg,
		Protocol:   protocol,
		Allowed:    allowed,
	})
	return err
}

type FQDNProxyServer struct {
	pb.UnimplementedFQDNProxyServer

	proxy *dnsproxy.DNSProxy
}

func (s *FQDNProxyServer) UpdateAllowed(ctx context.Context, rules *pb.FQDNRules) (*pb.Empty, error) {
	//TODO: implement
	cachedSelectorREEntry := make(dnsproxy.CachedSelectorREEntry)

	for key, rule := range rules.Rules.SelectorRegexMapping {
		regex, err := regexp.Compile(rule)
		if err != nil {
			return &pb.Empty{}, err
		}

		ids, ok := rules.Rules.SelectorIdentitiesMapping[key]
		if !ok {
			return &pb.Empty{}, errors.New(fmt.Sprintf("malformed message: key %s not found in identities mapping", key))
		}

		nids := make([]identity.NumericIdentity, len(ids.List))

		for i, id := range ids.List {
			nids[i] = identity.NumericIdentity(id)
		}

		selector := SimpleSelector{
			identities: nids,
			name:       key,
		}

		cachedSelectorREEntry[&selector] = regex
	}

	s.proxy.UpdateAllowedFromSelectorRegexes(rules.EndpointID, uint16(rules.DestPort), cachedSelectorREEntry)
	return &pb.Empty{}, nil
}

func (s *FQDNProxyServer) RemoveRestoredRules(ctx context.Context, endpointIDMsg *pb.EndpointID) (*pb.Empty, error) {
	s.proxy.RemoveRestoredRules(uint16(endpointIDMsg.EndpointID))

	return &pb.Empty{}, nil
}

func (s *FQDNProxyServer) GetRules(ctx context.Context, endpointIDMsg *pb.EndpointID) (*pb.RestoredRules, error) {
	rules := s.proxy.GetRules(uint16(endpointIDMsg.EndpointID))

	msg := &pb.RestoredRules{Rules: make(map[uint32]*pb.IPRules, len(rules))}

	for port, ipRules := range rules {
		msgRules := &pb.IPRules{
			List: make([]*pb.IPRule, 0, len(ipRules)),
		}
		for _, ipRule := range ipRules {
			msgRule := &pb.IPRule{
				Regex: ipRule.Re.String(),
				Ips:   make([]string, 0, len(ipRule.IPs)),
			}
			for ip, _ := range ipRule.IPs {
				msgRule.Ips = append(msgRule.Ips, ip)
			}

			msgRules.List = append(msgRules.List, msgRule)
		}

		msg.Rules[uint32(port)] = msgRules
	}

	return msg, nil
}

func newServer(proxy *dnsproxy.DNSProxy) *FQDNProxyServer {
	return &FQDNProxyServer{proxy: proxy}
}

func RunServer(port int, proxy *dnsproxy.DNSProxy) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterFQDNProxyServer(grpcServer, newServer(proxy))
	grpcServer.Serve(lis)
}

var _ policy.CachedSelector = &SimpleSelector{}

type SimpleSelector struct {
	identities []identity.NumericIdentity
	name       string
}

func (s *SimpleSelector) GetSelections() []identity.NumericIdentity {
	return s.identities
}

func (s *SimpleSelector) Selects(nid identity.NumericIdentity) bool {
	for _, id := range s.identities {
		if id == nid {
			return true
		}
	}
	return false
}

func (s *SimpleSelector) IsWildcard() bool {
	return false
}

func (s *SimpleSelector) IsNone() bool {
	return len(s.identities) == 0
}

func (s *SimpleSelector) String() string {
	return s.name
}
