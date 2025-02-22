// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/dns"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"

	standalonednsproxy "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

type updateOnDNSMsgFunc func(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) error

type FQDNDataServer struct {
	standalonednsproxy.UnimplementedFQDNDataServer

	ctx             context.Context
	closeServer     func()
	endpointManager endpointmanager.EndpointManager

	// streams is a map of the active streams and their cancel functions
	// Streams are added when a client(standalone dns proxy) subscribes to DNS policies and removed when the client closes the connection
	streams lock.Map[standalonednsproxy.FQDNData_StreamPolicyStateServer, context.CancelFunc]

	// updateOnDNSMsg is a function to update the DNS message in the cilium agent on receiving the FQDN mapping
	updateOnDNSMsg updateOnDNSMsgFunc

	// dnsMappingResult is a map of the dns request id and bool value for success/failure
	dnsMappingResult lock.Map[string, bool]

	// snapshotMutex is a mutex to protect the current state of the DNS rules
	snapshotMutex lock.Mutex

	// currentSnapshot is the current state of the DNS rules
	currentSnapshot map[identity.NumericIdentity]policy.SelectorPolicy

	// identityToIpMutex is a mutex to protect the current state of the identity to Ip mapping
	identityToIpMutex lock.Mutex

	// currentIdentityToIp is a map of the identity to list of Ips
	currentIdentityToIp map[identity.NumericIdentity][]net.IP
}

var (
	log  = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdn/server")
	kaep = keepalive.EnforcementPolicy{
		PermitWithoutStream: true, // Allow pings even when there are no active streams
	}
	kasp = keepalive.ServerParameters{
		Time:    5 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
		Timeout: 1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
	}
)

// StreamPolicyState is a bidirectional streaming RPC to subscribe to DNS policies
// SDP calls this method to subscribe to DNS policies
// For each stream, we start a goroutine to receive the DNS policies ACKs
// The flow of the method is as follows:
// 1. Add the stream to the map( called by the client i.e SDP)
// 2. Start a goroutine to receive the DNS policies ACKs for that particular client.
// 3. Send the current state of the DNS rules to the client (We store the current state fo DNS rules during the endpoint regeneration see UpdatePolicyRulesLocked)
// 4. Wait for the context to be done
func (s *FQDNDataServer) StreamPolicyState(stream standalonednsproxy.FQDNData_StreamPolicyStateServer) error {
	streamCtx, cancel := context.WithCancel(stream.Context())
	s.streams.Store(stream, cancel)

	go func() {
		<-streamCtx.Done()
		// If the client has closed the connection, the context will be done
		log.Info("Client has closed the connection, closing the stream")
		s.DeleteStream(stream)
	}()

	// Start a goroutine to receive the DNS policies ACKs
	go func() {
		if err := s.ReceiveDNSpolicesACK(stream); err != nil {
			log.Errorf("Error receiving DNS policies ACK: %v", err)
			cancel() // Cancel the context to close the stream
		}
	}()

	//Send the current state of the DNS rules
	go func() {
		log.Debugf("Sending current state of DNS rules")

		// Send the current state of the DNS rules
		if err := s.UpdatePolicyRulesLocked(nil, false); err != nil {
			log.Errorf("Error sending current state of DNS rules: %v", err)
			cancel() // Cancel the context to close the stream
		}
	}()

	log.Debugf("StreamPolicyState waiting for context to be done")
	select {
	case <-streamCtx.Done():
		log.Info("Closing the stream")
		s.DeleteStream(stream)
		return streamCtx.Err()
	case <-s.ctx.Done():
		s.closeServer()
		log.Info("StreamPolicyState done")
		return s.ctx.Err()
	}
}

// ReceiveDNSpolicesACK receives the DNS policies ACKs from the client
// If the success is false, we can send cancel signal to the channel
// in that case SDP will recreate the stream.
func (s *FQDNDataServer) ReceiveDNSpolicesACK(stream standalonednsproxy.FQDNData_StreamPolicyStateServer) error {
	for {
		select {
		case <-s.ctx.Done():
			s.closeServer()
			log.Info("Stopping the stream")
			return s.ctx.Err()
		case <-stream.Context().Done():
			log.Info("Stream context is finished, closing the stream")
			return stream.Context().Err()
		default:
			update, err := stream.Recv()
			if err != nil {
				log.Errorf("Failed to receive update: %v", err)
				return err
			}
			log.Debugf("Received update: %v", update)
			requestId := update.GetRequestId()
			_, ok := s.dnsMappingResult.Load(requestId)
			if !ok {
				log.Errorf("Received Message id not found %s", requestId)
			} else {
				log.Debugf("Received response for dns message id: %s", requestId)

				// We can send cancel signal to the channel if the response code is not NO_ERROR,
				// in that case SDP will recreate the stream.
				responseCode := update.GetResponse()
				if responseCode != standalonednsproxy.ResponseCode_RESPONSE_CODE_NO_ERROR {
					log.Errorf("Failed to update DNS policies")
					cancel, ok := s.streams.Load(stream)
					if ok {
						cancel()
					}
				}
			}
			// Delete the request from the map
			s.dnsMappingResult.Delete(requestId)
			log.Debugf("Deleted from local cache for dns message id: %s", requestId)
		}
	}
}

// NewServer creates a new FQDNDataServer which is used to handle the Standalone DNS Proxy grpc service
func NewServer(endpointManager endpointmanager.EndpointManager, updateOnDNSMsg updateOnDNSMsgFunc) *FQDNDataServer {
	ctx := context.Background()

	s := &FQDNDataServer{
		endpointManager:     endpointManager,
		updateOnDNSMsg:      updateOnDNSMsg,
		ctx:                 ctx,
		streams:             lock.Map[standalonednsproxy.FQDNData_StreamPolicyStateServer, context.CancelFunc]{},
		currentSnapshot:     make(map[identity.NumericIdentity]policy.SelectorPolicy),
		currentIdentityToIp: make(map[identity.NumericIdentity][]net.IP),
	}

	go func() {
		<-s.ctx.Done()
		log.Info("FQDN service context done, cleaning up resources")
		s.cleanupStreams()
		s.closeServer()
	}()

	return s
}

func convertToBytes(ips []net.IP) [][]byte {
	var byteIps [][]byte
	for _, ip := range ips {
		byteIps = append(byteIps, []byte(ip.String()))
	}
	return byteIps
}

// convertEndpointInfo converts the endpoint info to the format required by the standalone dns proxy
func (s *FQDNDataServer) convertEndpointInfo(ips []net.IP) []*standalonednsproxy.EndpointInfo {
	var endpointInfo = make(map[uint64][]net.IP)
	for _, ip := range ips {
		var epId uint64
		ep := s.endpointManager.LookupIP(netip.MustParseAddr(ip.String()))
		if ep == nil {
			// If the endpoint is not found, log a warning
			// This can happen for the endpoints that are not managed by this cilium agent
			log.Warnf("Endpoint not found for IP: %s", ip)
		} else {
			epId = ep.GetID()
		}
		endpointInfo[epId] = append(endpointInfo[epId], ip)
	}

	var convertedEndpointInfo []*standalonednsproxy.EndpointInfo
	for epId, ips := range endpointInfo {
		convertedEndpointInfo = append(convertedEndpointInfo, &standalonednsproxy.EndpointInfo{
			Id: epId,
			Ip: convertToBytes(ips),
		})
	}

	return convertedEndpointInfo
}

// OnIPIdentityCacheChange is a method to receive the IP identity cache change events
func (s *FQDNDataServer) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr types.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8) {
	s.identityToIpMutex.Lock()
	switch modType {
	case ipcache.Upsert:
		ip := cidr.AsIPNet().IP
		s.currentIdentityToIp[newID.ID] = append(s.currentIdentityToIp[newID.ID], ip)
	case ipcache.Delete:
		if oldID != nil {
			delete(s.currentIdentityToIp, oldID.ID)
		}
	}
	s.identityToIpMutex.Unlock()
	err := s.UpdatePolicyRulesLocked(nil, false)
	if err != nil {
		log.Errorf("Failed to update DNS rules: %v", err)
	}
}

// UpdatePolicyRulesLocked updates the current state of the DNS rules with the given policies and sends the current state of the DNS rules to the client
// This method is called:
// 1. when the DNS rules are updated during the endpoint regeneration, we store the state of the DNS rules with flag rulesUpdate as true
// 2. when the client subscribes to DNS policies, we send the current state of the DNS rules to the client(flag rulesUpdate as false)
// 3. when the IP identity cache changes, we update the current state of the identity to IP mapping and send the current state of the DNS rules to
// the client(flag rulesUpdate as false)
func (s *FQDNDataServer) UpdatePolicyRulesLocked(policies map[identity.NumericIdentity]policy.SelectorPolicy, rulesUpdate bool) error {
	s.snapshotMutex.Lock()
	defer s.snapshotMutex.Unlock()

	// We only update the rules if the rules are updated during the endpoint regeneration
	if rulesUpdate {
		s.currentSnapshot = policies
	}

	egressL7DnsPolicy := make([]*standalonednsproxy.DNSPolicy, 0, len(s.currentSnapshot))
	identityToEndpointMapping := make([]*standalonednsproxy.IdentityToEndpointMapping, 0, len(s.currentSnapshot))
	for identity, pol := range s.currentSnapshot {
		for l4, polSelTuple := range pol.RedirectFilters() {
			parseType := l4.GetL7Parser()
			switch parseType {
			case policy.ParserTypeDNS:
				selectorPolicy := polSelTuple.Policy
				cacheSelector := polSelTuple.Selector

				// Acquire the lock to read the current state of the identity to IP mapping
				s.identityToIpMutex.Lock()
				var dnsServersIdentity []uint32
				var dnsServers []*standalonednsproxy.DNSServer
				if cacheSelector != nil {
					for _, sel := range cacheSelector.GetSelections(versioned.Latest()) {
						dnsServersIdentity = append(dnsServersIdentity, sel.Uint32())
						identityToEndpointMapping = append(identityToEndpointMapping, &standalonednsproxy.IdentityToEndpointMapping{
							Identity:     sel.Uint32(),
							EndpointInfo: s.convertEndpointInfo(s.currentIdentityToIp[sel]),
						})
					}
					dnsServers = make([]*standalonednsproxy.DNSServer, 0, len(cacheSelector.GetSelections(versioned.Latest())))
					for _, dnsServerIdentity := range dnsServersIdentity {
						dnsServers = append(dnsServers, &standalonednsproxy.DNSServer{
							DnsServerIdentity: dnsServerIdentity,
							DnsServerPort:     uint32(l4.GetPort()),
							DnsServerProto:    uint32(l4.U8Proto),
						})
					}
				} else {
					dnsServers = make([]*standalonednsproxy.DNSServer, 0, 1)
					dnsServers = append(dnsServers, &standalonednsproxy.DNSServer{
						DnsServerPort:  uint32(l4.GetPort()),
						DnsServerProto: uint32(l4.U8Proto),
					})
				}
				var dnsPattern []string
				if selectorPolicy != nil && selectorPolicy.DNS != nil {
					dnsPattern = make([]string, 0, len(selectorPolicy.DNS))
					for _, dns := range selectorPolicy.DNS {
						if dns.MatchPattern != "" {
							dnsPattern = append(dnsPattern, dns.MatchPattern)
						}
						if dns.MatchName != "" {
							dnsPattern = append(dnsPattern, dns.MatchName)
						}
					}
				}
				epIPs := s.currentIdentityToIp[identity]
				for _, epIP := range epIPs {
					ep := s.endpointManager.LookupIP(netip.MustParseAddr(epIP.String()))
					if ep == nil {
						// If the endpoint is not found, log a warning
						// This can happen for the endpoints that are not managed by this cilium agent
						log.Warnf("Endpoint not found for IP: %s", epIP)
						continue
					}
					egressL7DnsPolicy = append(egressL7DnsPolicy, &standalonednsproxy.DNSPolicy{
						SourceEndpointId: uint32(ep.GetID()),
						DnsServers:       dnsServers,
						DnsPattern:       dnsPattern,
					})
				}

				identityToEndpointMapping = append(identityToEndpointMapping, &standalonednsproxy.IdentityToEndpointMapping{
					Identity:     identity.Uint32(),
					EndpointInfo: s.convertEndpointInfo(s.currentIdentityToIp[identity]),
				})
				s.identityToIpMutex.Unlock()
			}
		}
	}

	requestId := uuid.New().String()
	log.Debugf("Current EgressL7DnsPolicy: %v for request Id %v", egressL7DnsPolicy, requestId)
	dnsPolices := &standalonednsproxy.PolicyState{
		IdentityToEndpointMapping: identityToEndpointMapping,
		RequestId:                 requestId,
		EgressL7DnsPolicy:         egressL7DnsPolicy,
	}

	log.Debugf("Sending Policy updates to sdp: %v", dnsPolices)
	s.streams.Range(func(stream standalonednsproxy.FQDNData_StreamPolicyStateServer, cancel context.CancelFunc) bool {
		log.Debugf("Sending update to stream: %v", stream)
		s.dnsMappingResult.Store(requestId, false)
		if err := stream.Send(dnsPolices); err != nil {
			log.Errorf("Failed to send update: %v", err)
			// Cancel the goroutine and remove the stream from the map
			cancel()
		}
		return true
	})
	return nil
}

// DeleteStream deletes the stream from the map
func (s *FQDNDataServer) DeleteStream(stream standalonednsproxy.FQDNData_StreamPolicyStateServer) {
	_, ok := s.streams.Load(stream)
	if ok {
		log.Infof("Deleting stream: %v", stream)
		s.streams.Delete(stream)
	} else {
		log.Warnf("Stream not found: %v", stream)
	}

}

// cleanupStreams handles the cleanup of streams when the server's context is cancelled.
func (s *FQDNDataServer) cleanupStreams() {
	s.streams.Range(func(key standalonednsproxy.FQDNData_StreamPolicyStateServer, cancelFunc context.CancelFunc) bool {
		cancelFunc() // Ensure we cancel the context of each stream
		s.streams.Delete(key)
		return true
	})
	log.Info("All streams have been cleaned up")
}

// UpdateMappingRequest updates the FQDN mapping with the given data
// SDP sends the fqdn mapping to cilium agent
// Steps to update the mapping:
// 1. Get the endpoint from the IP
// 2. If the endpoint is not found, return an error
// 3. If the IPs are not empty, update the cilium agent with the mapping
func (s *FQDNDataServer) UpdateMappingRequest(ctx context.Context, mappings *standalonednsproxy.FQDNMapping) (*standalonednsproxy.UpdateMappingResponse, error) {
	log.Debugf("UpdateMappings %v", mappings)
	now := time.Now()
	var ips []netip.Addr

	endpointAddr := netip.MustParseAddr(string(mappings.SourceIp))

	ep := s.endpointManager.LookupIP(endpointAddr)
	if ep == nil {
		log.Errorf("endpoint not found for IP: %s", mappings.SourceIp)
		return &standalonednsproxy.UpdateMappingResponse{}, fmt.Errorf("endpoint not found for IP: %s", mappings.SourceIp)
	}

	recordIps := mappings.GetRecordIp()
	if len(recordIps) == 0 {
		// We don't have any IPs to update the mappings with
		return &standalonednsproxy.UpdateMappingResponse{
			Response: standalonednsproxy.ResponseCode_RESPONSE_CODE_NO_ERROR,
		}, nil
	}

	for _, ip := range recordIps {
		ips = append(ips, netip.MustParseAddr(string(ip)))
	}

	if mappings.GetResponseCode() == dns.RcodeSuccess {
		err := s.updateOnDNSMsg(now, ep, mappings.GetFqdn(), ips, int(mappings.GetTtl()), nil)
		if err != nil {
			return &standalonednsproxy.UpdateMappingResponse{}, fmt.Errorf("cannot update DNS cache: %w", err)
		}
	}

	return &standalonednsproxy.UpdateMappingResponse{
		Response: standalonednsproxy.ResponseCode_RESPONSE_CODE_NO_ERROR,
	}, nil
}

// RunServer starts the Standalone DNS Proxy grpc server on the given port
func RunServer(port int, server *FQDNDataServer) error {
	address := fmt.Sprintf("localhost:%d", port)
	log.Infof("Starting Standalone DNS Proxy grpc service on %s", address)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Errorf("failed to listen: %v", err)
		return err
	}
	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	standalonednsproxy.RegisterFQDNDataServer(grpcServer, server)

	if err := grpcServer.Serve(lis); err != nil {
		log.Errorf("failed to serve: %v", err)
		return err
	}

	closer := func() {
		grpcServer.GracefulStop()
	}
	server.closeServer = closer
	return nil
}
