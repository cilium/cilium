// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	ciliumdns "github.com/cilium/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/u8proto"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

var kacp = keepalive.ClientParameters{
	Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
	Timeout:             5 * time.Second,  // wait 1 second for ping ack before considering the connection dead
	PermitWithoutStream: true,             // send pings even without active streams
}

type StandaloneDNSProxyArgs struct {
	dnsproxy.DNSProxyConfig

	toFQDNsServerPort        uint16
	enableL7Proxy            bool
	enableStandaloneDNsProxy bool
}

type StandaloneDNSProxy struct {
	// DNSProxy is the standalone DNS proxy
	DNSProxy *dnsproxy.DNSProxy

	// Client is the client for the standalone DNS proxy to connect to the cilium agent
	Client pb.FQDNDataClient

	// connection stores the grpc connection to the cilium agent
	connection *grpc.ClientConn

	// ciliumAgentConnectionTrigger is the trigger to connect to the cilium agent
	ciliumAgentConnectionTrigger *trigger.Trigger

	// mu is the mutex to protect creation of multiple policy state stream in case of multiple triggers
	mu lock.Mutex

	// policyStateStream is the stream to subscribe to the policy state
	policyStateStream pb.FQDNData_StreamPolicyStateClient

	// cancelStreamPolicyStateStream is the cancel function for the PolicyState stream
	cancelStreamPolicyStateStream context.CancelFunc

	// args are the arguments for the standalone DNS proxy
	args *StandaloneDNSProxyArgs

	ipToIdentityCacheMu lock.Mutex
	ipToIdentityCache   map[string]uint32

	ipToEndpointIdCacheMu lock.Mutex
	ipToEndpointIdCache   map[string]uint64

	log *slog.Logger
}

// NewStandaloneDNSProxy creates a new standalone DNS proxy
func NewStandaloneDNSProxy(args *StandaloneDNSProxyArgs, logger *slog.Logger) (*StandaloneDNSProxy, error) {
	if args.toFQDNsServerPort == 0 {
		logger.Error("toFQDNsServerPort is 0")
		return nil, errors.New("toFQDNsServerPort is 0")
	}

	return &StandaloneDNSProxy{
		args:                args,
		ipToIdentityCache:   make(map[string]uint32),
		ipToEndpointIdCache: make(map[string]uint64),
		log:                 logger,
	}, nil
}

func (sdp *StandaloneDNSProxy) StopStandaloneDNSProxy() error {
	if sdp.DNSProxy != nil {
		sdp.DNSProxy.Cleanup()
	}

	err := sdp.closeConnection()
	if err != nil {
		sdp.log.Error("Failed to close connection", logfields.Error, err)
		return err
	}
	return nil
}

// CreateClient creates a client for the cilium agent connection
// 1. It checks if connection is created, if not it returns an error and triggers the cilium agent connection trigger
// 2. Else it creates the client
// 3. If the policy state stream is not created, it creates the stream
// Note: This function is called with a mutex lock in the caller function because there can be multiple triggers trying to
// create the stream at the same time
func (sdp *StandaloneDNSProxy) CreateClient(ctx context.Context) error {
	var err error
	defer func() {
		if err != nil {
			sdp.log.Error("Failed to create cilium agent connection", logfields.Error, err)
			sdp.closeConnection()
			sdp.ciliumAgentConnectionTrigger.TriggerWithReason("Failed to create cilium agent connection")
		}
	}()

	if sdp.connection == nil {
		sdp.log.Error("Connection is nil")
		return fmt.Errorf("connection is nil")
	}

	// Create the client
	sdp.Client = pb.NewFQDNDataClient(sdp.connection)

	if sdp.policyStateStream == nil {
		err = sdp.createStreamPolicyStateStream(ctx)
		if err != nil {
			sdp.log.Error("Failed to create subscription stream", logfields.Error, err)
			return err
		}
	}
	sdp.log.Debug("Successfully created client for Cilium agent")

	return nil
}

// ConnectToCiliumAgent creates a connection to the cilium agent
// It returns an error if the connection is not successful and triggers the cilium agent connection trigger
func (sdp *StandaloneDNSProxy) ConnectToCiliumAgent() error {
	var err error
	defer func() {
		if err != nil {
			sdp.log.Error("Failed to connect to cilium agent", logfields.Error, err)
			sdp.ciliumAgentConnectionTrigger.TriggerWithReason("Failed to connect to cilium agent")
		}
	}()

	if sdp.connection != nil {
		return nil
	}

	address := fmt.Sprintf("localhost:%d", sdp.args.toFQDNsServerPort)

	scopedLog := sdp.log.With(
		logfields.Address, address,
		logfields.Port, sdp.args.toFQDNsServerPort,
	)
	scopedLog.Info("Connecting to server")
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithKeepaliveParams(kacp))
	if err != nil {
		scopedLog.Error("Failed to connect to server", logfields.Error, err)
		return err
	}

	scopedLog.Info("Connected to server")
	sdp.connection = conn

	return nil // Successfully connected
}

// StartStandaloneDNSProxy starts the standalone DNS proxy and creates the cilium agent connection trigger
// The flow is as follows:
// 1. It starts the DNS Proxy
// 2. It creates the cilium agent connection trigger
// 3. It triggers the cilium agent connection trigger
func (sdp *StandaloneDNSProxy) StartStandaloneDNSProxy() error {
	var err error

	if !sdp.args.enableL7Proxy {
		sdp.log.Info("L7 Proxy is disabled")
		return nil
	}

	if !sdp.args.enableStandaloneDNsProxy {
		sdp.log.Info("Standalone DNS Proxy is disabled")
		return nil
	}

	// Initialize the DNS Proxy
	sdp.DNSProxy, err = dnsproxy.StartDNSProxy(sdp.args.DNSProxyConfig, sdp.LookupEPByIP, sdp.LookupSecIDByIP, sdp.LookupIPsBySecID, sdp.NotifyOnDNSMsg)
	if err != nil {
		sdp.log.Error("Failed to start DNS Proxy", logfields.Error, err)
		return err
	}
	sdp.log.Info("DNS Proxy started on",
		logfields.Address, sdp.args.Address,
		logfields.Port, sdp.args.Port)

	// Create the cilium agent connection trigger
	err = sdp.createciliumAgentConnectionTrigger()
	if err != nil {
		sdp.log.Error("Failed to create the trigger for connecting to Cilium agent", logfields.Error, err)
		return err
	}

	// trigger the cilium agent connection
	sdp.ciliumAgentConnectionTrigger.TriggerWithReason("Start standalone DNS proxy")
	return nil
}

// createciliumAgentConnectionTrigger creates a trigger to connect to the cilium agent
// 1. It tries to connect to the cilium agent
// 2. If the connection is successful, it tries to start the grpc streams
// 3. If the streams are started, it tries to subscribe to the policy state as go routine
func (sdp *StandaloneDNSProxy) createciliumAgentConnectionTrigger() error {
	var err error
	sdp.ciliumAgentConnectionTrigger, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "start-cilium-agent-connection",
		MinInterval: 5 * time.Second,
		TriggerFunc: func(reasons []string) {
			defer func() {
				if r := recover(); r != nil {
					sdp.log.Error("Recovered from panic in trigger function", logfields.Error, r)
				}
			}()
			sdp.log.Info("Triggering cilium agent connection", logfields.Reasons, reasons)
			// 1. Try creating the connection to the cilium agent
			err := sdp.ConnectToCiliumAgent()
			if err != nil {
				sdp.log.Error("Failed to connect to cilium agent", logfields.Error, err)
				return
			}

			sdp.mu.Lock()
			defer sdp.mu.Unlock()
			// 2. Try starting the cilium agent connection
			// only create the client if no stream is already open
			// Imagine a scenarios where two triggers are fired at the same time
			// and both try to create the client at the same time
			// Due to the mutex, only one of them will create the client and start the stream
			// The other one will just return
			if sdp.policyStateStream == nil {
				ctx, cancel := context.WithCancel(context.Background())

				err = sdp.CreateClient(ctx)
				if err != nil {
					sdp.log.Error("Failed to create client", logfields.Error, err)
					cancel()
					return
				}

				// 3. Try to subscribe to the policy state
				sdp.cancelStreamPolicyStateStream = cancel // Store the cancel function for later use
				go sdp.streamPolicyState(ctx)
			}
		},
	})
	if err != nil {
		sdp.log.Error("Failed to create trigger", logfields.Error, err)
		return err // Return the error after logging
	}
	return nil
}

// Note: isHost is always false as it is not used in the current implementation
// TODO: Remove isHost from the function signature
func (sdp *StandaloneDNSProxy) LookupEPByIP(ip netip.Addr) (ep *endpoint.Endpoint, isHost bool, err error) {
	sdp.ipToIdentityCacheMu.Lock()
	defer sdp.ipToIdentityCacheMu.Unlock()
	sdp.ipToEndpointIdCacheMu.Lock()
	defer sdp.ipToEndpointIdCacheMu.Unlock()

	sdp.log.Debug("Lookup ep by IP", logfields.IPAddr, ip.String())
	// find the identity from the cache
	secId, ok := sdp.ipToIdentityCache[ip.String()]
	if !ok {
		sdp.log.Error("Failed to get identity for IP", logfields.IPAddr, ip.String())
		return nil, false, fmt.Errorf("failed to get identity for IP %s", ip.String())
	}

	id, ok := sdp.ipToEndpointIdCache[ip.String()]
	if !ok {
		sdp.log.Error("Endpoint ID not found for IP", logfields.IPAddr, ip.String())
		return nil, false, fmt.Errorf("endpoint ID not found for IP %s", ip.String())
	}

	endpt := &endpoint.Endpoint{
		ID: uint16(id),
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(secId),
		},
	}
	sdp.log.Debug("Endpoint Identity found",
		logfields.EndpointID, endpt.ID,
		logfields.Identity, endpt.SecurityIdentity.ID,
		logfields.IPAddr, ip.String())

	return endpt, false, nil
}

// LookupIPsBySecID is used by cilium agent during the restoration of the DNS rules.
// In case of standalone DNS proxy, it is not used as the DNS rules are restored
// from the embedded DNS proxy.
func (sdp *StandaloneDNSProxy) LookupIPsBySecID(nid identity.NumericIdentity) []string {
	return nil
}

func (sdp *StandaloneDNSProxy) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	sdp.ipToIdentityCacheMu.Lock()
	defer sdp.ipToIdentityCacheMu.Unlock()

	sdp.log.Debug("Look up SecID by IP", logfields.IPAddr, ip.String())

	id, ok := sdp.ipToIdentityCache[ip.String()]
	if !ok {
		sdp.log.Error("Failed to get identity for IP", logfields.IPAddr, ip.String())
		return ipcache.Identity{}, false
	}

	sdp.log.Debug("Identity found",
		logfields.Identity, id,
		logfields.IPAddr, ip.String())
	return ipcache.Identity{
		ID:     identity.NumericIdentity(id),
		Source: source.Local, // Local source means the identity is from the local agent
	}, true
}

func (sdp *StandaloneDNSProxy) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *ciliumdns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	qname, responseIPs, TTL, _, rcode, _, _, err := dnsproxy.ExtractMsgDetails(msg)
	if err != nil {
		sdp.log.Error("Cannot extract DNS message details", logfields.Error, err)
		return err
	}
	scopedLog := sdp.log.With(
		logfields.Name, qname,
		logfields.IPAddr, epIPPort,
		logfields.Response, rcode,
		logfields.Protocol, protocol,
		logfields.EndpointID, ep.ID,
		logfields.IPAddrs, responseIPs,
	)
	var ips [][]byte
	for _, i := range responseIPs {
		ips = append(ips, []byte(i.String()))
	}

	sourceIp, _, err := net.SplitHostPort(epIPPort)
	if err != nil {
		scopedLog.Error("Failed to split IP:Port", logfields.Error, err)
		return err
	}

	sourceIdentity, err := ep.GetSecurityIdentity()
	if err != nil {
		scopedLog.Error("Failed to get security identity", logfields.Error, err)
		return err
	}
	message := &pb.FQDNMapping{
		Fqdn:           qname,
		RecordIp:       ips,
		Ttl:            TTL,
		SourceIp:       []byte(sourceIp),
		SourceIdentity: uint32(sourceIdentity.ID),
		ResponseCode:   uint32(rcode),
	}

	if sdp.Client == nil {
		sdp.log.Error("Client is nil")
		return fmt.Errorf("client is nil")
	}
	result, err := sdp.Client.UpdateMappingRequest(context.Background(), message)
	scopedLog.Debug("Update mapping request response",
		logfields.Response, result,
		logfields.Error, err)
	if err != nil {
		scopedLog.Error("Failed to send FQDN Mapping message", logfields.Error, err)
		return err
	}

	return nil
}

// streamPolicyState subscribes to the policy state
// 1. Tries to get the stream connected
// 2. If the stream is connected, it waits for the policy state to be received
func (sdp *StandaloneDNSProxy) streamPolicyState(ctx context.Context) error {
	var err error
	defer func() {
		if err != nil {
			sdp.closePolicyStateStream()
			reason := "Failed to subscribe to policy state"
			switch status.Code(err) {
			case codes.Unavailable:
				sdp.closeConnection()
				reason = "DNS server unavailable"
			default:
				if errors.Is(err, io.EOF) {
					sdp.closeConnection()
					reason = "Received EOF from policy state stream"
					sdp.log.Error("Received EOF from policy state stream")
				} else {
					sdp.log.Error("Failed to subscribe to policy state", logfields.Error, err)
				}
			}
			sdp.ciliumAgentConnectionTrigger.TriggerWithReason(reason)
		}
		sdp.cancelStreamPolicyStateStream()
	}()

	for {
		select {
		case <-ctx.Done():
			// Context was cancelled, exit goroutine
			sdp.log.Info("Stopping subscription to policy state")
			return nil
		default:
			sdp.log.Debug("Waiting for policy state")
			policyState, recvErr := sdp.policyStateStream.Recv()
			if recvErr != nil {
				if errors.Is(recvErr, io.EOF) || status.Code(recvErr) == codes.Unavailable {
					sdp.log.Error("Policy state stream closed", logfields.Error, recvErr)
					err = recvErr
					return err
				}
				sdp.log.Error("Failed to receive policy state", logfields.Error, recvErr)
				err = recvErr // Set the outer err for the deferred function to handle.
				return err
			}

			response := &pb.PolicyStateResponse{
				RequestId: policyState.GetRequestId(),
			}
			revertStack, err := sdp.UpdatePolicyState(policyState)
			if err != nil {
				sdp.log.Error("Failed to update policy state", logfields.Error, err)
				revertStack.Revert()
				err = sdp.policyStateStream.Send(response)
				if err != nil {
					sdp.log.Error("Failed to send policy state response", logfields.Error, err)
					return err
				}
				return err
			}
			response.Response = pb.ResponseCode_RESPONSE_CODE_NO_ERROR
			err = sdp.policyStateStream.Send(response)
			if err != nil {
				sdp.log.Error("Failed to send policy state response", logfields.Error, err)
				return err
			}
		}
	}
}

func (sdp *StandaloneDNSProxy) closePolicyStateStream() {
	if sdp.policyStateStream != nil {
		err := sdp.policyStateStream.CloseSend()
		if err != nil {
			sdp.log.Error("Failed to close policy state stream", logfields.Error, err)
		}
		sdp.policyStateStream = nil
	}
}

func (sdp *StandaloneDNSProxy) closeConnection() error {
	if sdp.connection != nil {
		err := sdp.connection.Close()
		if err != nil {
			sdp.log.Error("Failed to close connection", logfields.Error, err)
			return err
		}
		sdp.connection = nil
	}
	return nil
}

// createStreamPolicyStateStream creates a subscription stream to the policy state
func (sdp *StandaloneDNSProxy) createStreamPolicyStateStream(ctx context.Context) error {
	if sdp.Client == nil {
		sdp.log.Error("Client is nil")
		return fmt.Errorf("client is nil")
	}

	if sdp.policyStateStream != nil {
		sdp.log.Warn("Policy state stream is not nil")
		sdp.closePolicyStateStream()
	}

	stream, err := sdp.Client.StreamPolicyState(ctx)
	if err != nil {
		sdp.log.Error("Failed to subscribe to policy state", logfields.Error, err)
		return err
	}
	sdp.policyStateStream = stream
	return nil
}

// UpdatePolicyState updates the DNS rules in the standalone DNS proxy
// 1. It updates the ip to identity cache and ip to endpoint id cache
// 2. It updates the DNS rules in the standalone DNS proxy
// The input is the policy state received from the cilium agent as :
//
//	PolicyState : {
//	  EgressL7DnsPolicy : [
//	    {
//	    SourceEndpointId : 1
//	    DnsServers : [{
//	      DnsServerIdentity : 2
//	      DnsServerPort : 53
//	      DnsServerProto : 17
//	    	},
//	    	{
//	      DnsServerIdentity : 3
//	      DnsServerPort : 53
//	      DnsServerProto : 17
//	    	}]
//	    DnsPattern : ["www.example.com"]
//	    },
//	    {
//	    SourceEndpointId : 1
//	    DnsServers : [{
//	      DnsServerIdentity : 2
//	      DnsServerPort : 54
//	      DnsServerProto : 17
//	    	}]
//	    DnsPattern : ["www.test.com"]
//	    }
//	  ]
//	  IdentityToEndpointMapping : []
//	}
func (sdp *StandaloneDNSProxy) UpdatePolicyState(rules *pb.PolicyState) (revert.RevertStack, error) {
	sdp.ipToIdentityCacheMu.Lock()
	defer sdp.ipToIdentityCacheMu.Unlock()
	sdp.ipToEndpointIdCacheMu.Lock()
	defer sdp.ipToEndpointIdCacheMu.Unlock()

	var revertStack revert.RevertStack
	identityToEndpointMapping := rules.GetIdentityToEndpointMapping()

	// Update the ip to identity cache and ip to endpoint id cache
	for _, mapping := range identityToEndpointMapping {
		for _, epInfo := range mapping.GetEndpointInfo() {
			for _, ip := range epInfo.GetIp() {
				sdp.ipToIdentityCache[net.IP(ip).String()] = mapping.GetIdentity()
				if epInfo.GetId() != 0 {
					sdp.ipToEndpointIdCache[net.IP(ip).String()] = epInfo.GetId()
				}
			}
		}
	}

	endpointIdToRule := make(map[uint32]map[restore.PortProto]map[policy.CachedSelector][]string)
	for _, rule := range rules.GetEgressL7DnsPolicy() {

		portProtoToServerIdentity := make(map[restore.PortProto][]uint32)
		for _, dnsServer := range rule.GetDnsServers() {
			portProto := restore.MakeV2PortProto(uint16(dnsServer.GetDnsServerPort()), u8proto.U8proto(dnsServer.GetDnsServerProto()))
			portProtoToServerIdentity[portProto] = append(portProtoToServerIdentity[portProto], dnsServer.GetDnsServerIdentity())
		}

		portProtoToDNSrules := make(map[restore.PortProto]map[policy.CachedSelector][]string)
		for portProto, identities := range portProtoToServerIdentity {
			cs := make(map[policy.CachedSelector][]string)
			cs[&dnsproxy.DnsServerIdentity{Identities: identities}] = rule.GetDnsPattern()
			portProtoToDNSrules[portProto] = cs
		}

		epId := rule.GetSourceEndpointId()
		if _, ok := endpointIdToRule[epId]; !ok {
			endpointIdToRule[epId] = make(map[restore.PortProto]map[policy.CachedSelector][]string)
		}

		for portProto, cs := range portProtoToDNSrules {
			if _, ok := endpointIdToRule[epId][portProto]; !ok {
				endpointIdToRule[epId][portProto] = make(map[policy.CachedSelector][]string)
			}

			for k, v := range cs {
				endpointIdToRule[epId][portProto][k] = v
			}
		}
	}

	for epId, rules := range endpointIdToRule {
		for portProto, cs := range rules {
			revertFunc, err := sdp.DNSProxy.UpdateAllowedStandaloneDnsProxy(uint64(epId), portProto, cs)
			if err != nil {
				sdp.log.Error("Failed to update DNS rules",
					logfields.EndpointID, epId,
					logfields.Port, portProto.Protocol(),
					logfields.Protocol, portProto.Protocol(),
					logfields.Error, err)
				return revertStack, err
			}
			revertStack.Push(revertFunc)
		}
	}

	return revertStack, nil
}
