// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	ciliumdns "github.com/cilium/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/u8proto"

	standalonednsproxy "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

var kacp = keepalive.ClientParameters{
	Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
	Timeout:             5 * time.Second,  // wait 1 second for ping ack before considering the connection dead
	PermitWithoutStream: true,             // send pings even without active streams
}

type StandaloneDNSProxyArgs struct {
	dnsproxy.DNSProxyConfig

	toFqdnServerPort         uint16
	enableL7Proxy            bool
	enableStandaloneDNsProxy bool
}

type StandaloneDNSProxy struct {
	// DNSProxy is the standalone DNS proxy
	DNSProxy *dnsproxy.DNSProxy

	// Client is the client for the standalone DNS proxy to connect to the cilium agent
	Client standalonednsproxy.FQDNDataClient

	// connection stores the grpc connection to the cilium agent
	connection *grpc.ClientConn

	// ciliumAgentConnectionTrigger is the trigger to connect to the cilium agent
	ciliumAgentConnectionTrigger *trigger.Trigger

	// mu is the mutex to protect creation of multiple policy state stream in case of multiple triggers
	mu lock.Mutex

	// policyStateStream is the stream to subscribe to the policy state
	policyStateStream standalonednsproxy.FQDNData_StreamPolicyStateClient

	// cancelStreamPolicyStateStream is the cancel function for the PolicyState stream
	cancelStreamPolicyStateStream context.CancelFunc

	// args are the arguments for the standalone DNS proxy
	args *StandaloneDNSProxyArgs

	ipToIdentityCache map[string]uint32

	ipToEndpointIdCache map[string]uint64
}

// NewStandaloneDNSProxy creates a new standalone DNS proxy
func NewStandaloneDNSProxy(args *StandaloneDNSProxyArgs) (*StandaloneDNSProxy, error) {
	if args.toFqdnServerPort == 0 {
		log.Error("toFqdnServerPort is 0")
		return nil, errors.New("toFqdnServerPort is 0")
	}

	return &StandaloneDNSProxy{
		args:                args,
		ipToIdentityCache:   make(map[string]uint32),
		ipToEndpointIdCache: make(map[string]uint64),
	}, nil
}

func (sdp *StandaloneDNSProxy) StopStandaloneDNSProxy() error {
	if sdp.DNSProxy != nil {
		sdp.DNSProxy.Cleanup()
	}

	err := sdp.closeConnection()
	if err != nil {
		log.WithError(err).Error("Failed to close connection")
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
			log.WithError(err).Error("Failed to start cilium agent connection")
			sdp.closeConnection()
			sdp.ciliumAgentConnectionTrigger.TriggerWithReason("Failed to start cilium agent connection")
		}
	}()

	if sdp.connection == nil {
		log.Error("Connection is nil")
		return fmt.Errorf("connection is nil")
	}

	// Create the client
	sdp.Client = standalonednsproxy.NewFQDNDataClient(sdp.connection)

	if sdp.policyStateStream == nil {
		err = sdp.createStreamPolicyStateStream(ctx)
		if err != nil {
			log.WithError(err).Error("Failed to create subscription stream")
			return err
		}
	}
	log.Debugf("Successfully created client for Cilium agent")

	return nil
}

// ConnectToCiliumAgent creates a connection to the cilium agent
// It returns an error if the connection is not successful and triggers the cilium agent connection trigger
func (sdp *StandaloneDNSProxy) ConnectToCiliumAgent() error {
	var err error
	defer func() {
		if err != nil {
			log.Errorf("Failed to connect to cilium agent: %v", err)
			sdp.ciliumAgentConnectionTrigger.TriggerWithReason("Failed to connect to cilium agent")
		}
	}()

	if sdp.connection != nil {
		return nil
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())
	opts = append(opts, grpc.WithKeepaliveParams(kacp))

	address := fmt.Sprintf("localhost:%d", sdp.args.toFqdnServerPort)

	log.Infof("Connecting to server %v", address)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5) // 5 seconds timeout
	defer cancel()

	conn, err := grpc.DialContext(ctx, address, opts...)
	if err != nil {
		log.Errorf("Failed to connect to server %v at address %s", err, address)
		return err
	}
	log.Infof("Connected to server %v", address)
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
		log.Info("L7 Proxy is disabled")
		return nil
	}

	if !sdp.args.enableStandaloneDNsProxy {
		log.Info("Standalone DNS Proxy is disabled")
		return nil
	}

	// Initialize the DNS Proxy
	sdp.DNSProxy, err = dnsproxy.StartDNSProxy(sdp.args.DNSProxyConfig, sdp.LookupEPByIP, sdp.LookupSecIDByIP, sdp.LookupIPsBySecID, sdp.NotifyOnDNSMsg)
	if err != nil {
		log.WithError(err).Fatal("Failed to start DNS Proxy")
		return err
	}
	log.Infof("DNS Proxy started on %s:%d", sdp.args.Address, sdp.args.Port)

	// Create the cilium agent connection trigger
	err = sdp.createciliumAgentConnectionTriggerTrigger()
	if err != nil {
		log.WithError(err).Error("Failed to create the trigger for connecting to Cilium agent")
		return err
	}

	// trigger the cilium agent connection
	sdp.ciliumAgentConnectionTrigger.TriggerWithReason("Start standalone DNS proxy")
	return nil
}

// createciliumAgentConnectionTriggerTrigger creates a trigger to connect to the cilium agent
// 1. It tries to connect to the cilium agent
// 2. If the connection is successful, it tries to start the grpc streams
// 3. If the streams are started, it tries to subscribe to the policy state as go routine
func (sdp *StandaloneDNSProxy) createciliumAgentConnectionTriggerTrigger() error {
	var err error
	sdp.ciliumAgentConnectionTrigger, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "start-cilium-agent-connection",
		MinInterval: 5 * time.Second,
		TriggerFunc: func(reasons []string) {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("Recovered from panic in trigger function: %v", r)
				}
			}()
			log.Infof("Triggering cilium agent connection: %v", reasons)
			// 1. Try creating the connection to the cilium agent
			err := sdp.ConnectToCiliumAgent()
			if err != nil {
				log.WithError(err).Error("Failed to connect to cilium agent")
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
					log.WithError(err).Error("Failed to create client")
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
		log.Errorf("Failed to create trigger: %v", err)
		return err // Return the error after logging
	}
	return nil
}

// Note: isHost is always false as it is not used in the current implementation
// TODO: Remove isHost from the function signature
func (sdp *StandaloneDNSProxy) LookupEPByIP(ip netip.Addr) (ep *endpoint.Endpoint, isHost bool, err error) {
	log.Debugf("LookupEPByIP: %s", ip.String())

	// find the identity from the cache
	secId, ok := sdp.ipToIdentityCache[ip.String()]
	if !ok {
		log.Errorf("Failed to get identity for IP %s", ip.String())
		return nil, false, fmt.Errorf("failed to get identity for IP %s", ip.String())
	}

	id, ok := sdp.ipToEndpointIdCache[ip.String()]
	if !ok {
		log.Errorf("Endpoint ID not found for IP %s", ip.String())
		return nil, false, fmt.Errorf("endpoint ID not found for IP %s", ip.String())
	}

	endpt := &endpoint.Endpoint{
		ID: uint16(id),
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(secId),
		},
	}
	log.Debugf("Endpoint Identity found: %v", endpt)

	return endpt, false, nil
}

func (sdp *StandaloneDNSProxy) LookupIPsBySecID(nid identity.NumericIdentity) []string {
	return nil
}

func (sdp *StandaloneDNSProxy) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	log.Debugf("LookupSecIDByIP: %s", ip.String())

	id, ok := sdp.ipToIdentityCache[ip.String()]
	if !ok {
		log.Errorf("Failed to get identity for IP %s", ip.String())
		return ipcache.Identity{}, false
	}

	log.Debugf("Identity found: %v", id)
	return ipcache.Identity{
		ID:     identity.NumericIdentity(id),
		Source: source.Local, // Local source means the identity is from the local agent
	}, true
}

func (sdp *StandaloneDNSProxy) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr netip.AddrPort, msg *ciliumdns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	log.Debugf("Received DNS message: %v", msg)
	qname, responseIPs, TTL, _, rcode, _, _, err := dnsproxy.ExtractMsgDetails(msg)
	if err != nil {
		log.WithError(err).Error("cannot extract DNS message details")
		return err
	}

	var ips [][]byte
	for _, i := range responseIPs {
		log.Debugf("%s is mapped to %s", qname, i.String())
		ips = append(ips, []byte(i.String()))
	}

	sourceIp, _, err := net.SplitHostPort(epIPPort)
	if err != nil {
		log.WithError(err).Error("Failed to split IP:Port")
		return err
	}

	sourceIdentity, err := ep.GetSecurityIdentity()
	if err != nil {
		log.WithError(err).Error("Failed to get security identity")
	}
	message := &standalonednsproxy.FQDNMapping{
		Fqdn:           qname,
		RecordIp:       ips,
		Ttl:            TTL,
		SourceIp:       []byte(sourceIp),
		SourceIdentity: uint32(sourceIdentity.ID),
		ResponseCode:   uint32(rcode),
	}
	log.Debugf("Sending FQDN Mapping message: %v", message)
	if sdp.Client == nil {
		log.Error("Client is nil")
		return fmt.Errorf("client is nil")
	}
	result, err := sdp.Client.UpdateMappingRequest(context.Background(), message)
	log.Debugf("Received result from FQDN mapping stream %v", result)
	if err != nil {
		log.WithError(err).Error("Failed to send FQDN Mapping message")
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
					log.Error("Received EOF from policy state stream")
				} else {
					log.WithError(err).Error("Failed to subscribe to policy state")
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
			log.Info("Stopping subscription to policy state")
			return nil
		default:
			log.Debugf("Waiting for policy state")
			policyState, recvErr := sdp.policyStateStream.Recv()
			if recvErr != nil {
				if errors.Is(recvErr, io.EOF) || status.Code(recvErr) == codes.Unavailable {
					log.WithError(recvErr).Error("Policy state stream closed")
					err = recvErr
					return err
				}
				log.WithError(recvErr).Error("Failed to receive policy state")
				err = recvErr // Set the outer err for the deferred function to handle.
				return err
			}
			log.WithField("policyState", policyState).Debug("Received policy state")

			response := &standalonednsproxy.PolicyStateResponse{
				RequestId: policyState.GetRequestId(),
			}
			revertStack, err := sdp.UpdatePolicyState(policyState)
			if err != nil {
				log.WithError(err).Error("Failed to update policy state")
				revertStack.Revert()
				err = sdp.policyStateStream.Send(response)
				if err != nil {
					log.WithError(err).Error("Failed to send policy state response")
					return err
				}
				return err
			}
			response.Response = standalonednsproxy.ResponseCode_RESPONSE_CODE_NO_ERROR
			err = sdp.policyStateStream.Send(response)
			if err != nil {
				log.WithError(err).Error("Failed to send policy state response")
				return err
			}
		}
	}
}

func (sdp *StandaloneDNSProxy) closePolicyStateStream() {
	if sdp.policyStateStream != nil {
		err := sdp.policyStateStream.CloseSend()
		if err != nil {
			log.Errorf("Failed to close policy state stream: %v", err)
		}
		sdp.policyStateStream = nil
	}
}

func (sdp *StandaloneDNSProxy) closeConnection() error {
	if sdp.connection != nil {
		err := sdp.connection.Close()
		if err != nil {
			log.Errorf("Failed to close connection: %v", err)
			return err
		}
		sdp.connection = nil
	}
	return nil
}

// createStreamPolicyStateStream creates a subscription stream to the policy state
func (sdp *StandaloneDNSProxy) createStreamPolicyStateStream(ctx context.Context) error {
	if sdp.Client == nil {
		log.Error("Client is nil")
		return fmt.Errorf("client is nil")
	}

	if sdp.policyStateStream != nil {
		log.Error("Policy state stream is not nil")
		sdp.closePolicyStateStream()
	}

	stream, err := sdp.Client.StreamPolicyState(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to subscribe to policy state")
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
func (sdp *StandaloneDNSProxy) UpdatePolicyState(rules *standalonednsproxy.PolicyState) (revert.RevertStack, error) {
	log.Debugf("Received policy state: %v", rules)

	var revertStack revert.RevertStack
	identityToEndpointMapping := rules.GetIdentityToEndpointMapping()

	// Update the ip to identity cache and ip to endpoint id cache
	for _, mapping := range identityToEndpointMapping {
		for _, epInfo := range mapping.GetEndpointInfo() {
			for _, ip := range epInfo.GetIp() {
				sdp.ipToIdentityCache[string(ip)] = mapping.GetIdentity()
				if epInfo.GetId() != 0 {
					sdp.ipToEndpointIdCache[string(ip)] = epInfo.GetId()
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
				log.WithError(err).Error("Failed to update DNS rules")
				return revertStack, err
			}
			revertStack.Push(revertFunc)
		}
	}

	return revertStack, nil
}
