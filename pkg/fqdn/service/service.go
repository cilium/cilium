// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

// FQDNDataServer is the server for the standalone DNS proxy grpc server
// It is responsible for handling the FQDN mapping requests from the SDP
// and sending the DNS Policy updates to the SDP.
type FQDNDataServer struct {
	pb.UnimplementedFQDNDataServer

	// port is the port on which the standalone DNS proxy grpc server will run
	port int

	// grpcServer is the grpc server for the standalone DNS proxy
	grpcServer *grpc.Server

	endpointsLookup endpointmanager.EndpointsLookup

	// db is the database used to store the policy rules table
	db *statedb.DB

	// policyRulesTable is the table used to store the policy rules
	// Changes to this table are used to send the current state of the DNS rules to the client
	policyRulesTable statedb.RWTable[PolicyRules]

	// updateOnDNSMsg is a function to update the DNS message in the cilium agent on receiving the FQDN mapping
	updateOnDNSMsg messagehandler.DNSMessageHandler

	// identityToIPsTable is a table for storing the current state of the identity to IPs mapping
	identityToIPsTable statedb.RWTable[identityToIPs]

	// prefixLengths tracks the unique set of prefix lengths for IPv4 and
	// IPv6 addresses in order to optimize longest prefix match lookups.
	prefixLengths *counter.PrefixLengthCounter

	// log is the logger for the FQDNDataServer
	log *slog.Logger

	// listener is used to create a net.Listener when starting the grpc server
	listener listenConfig

	// enabled indicates whether the standalone DNS proxy is enabled
	// This field is set to true only when ALL the following conditions are met:
	//
	// | Flag/Setting                           | Required Value | Description                                    |
	// |----------------------------------------|----------------|------------------------------------------------|
	// | EnableStandaloneDNSProxy               | true           | Feature flag to enable standalone DNS proxy   |
	// | DaemonConfig.EnableL7Proxy             | true           | L7 proxy must be enabled as a prerequisite    |
	// | DaemonConfig.ToFQDNsProxyPort          | > 0            | Valid port for FQDN proxy                     |
	// | Config.StandaloneDNSProxyServerPort    | > 0            | Valid port for standalone DNS proxy server    |
	//
	// If ANY of these conditions is not met, enabled will be false and the standalone
	// DNS proxy will not function. The IsEnabled() method returns this field's value.
	enabled bool
}

type PolicyRules struct {
	Identity    identity.NumericIdentity
	PolicyRules []*pb.DNSPolicy
}

// TableHeader implements statedb.TableWritable.
func (p PolicyRules) TableHeader() []string {
	return []string{"Identity", "PolicyRules"}
}

// TableRow implements statedb.TableWritable.
func (p PolicyRules) TableRow() []string {
	var policyDetails []string
	for i, rule := range p.PolicyRules {
		var servers []string
		for _, server := range rule.DnsServers {
			servers = append(servers, fmt.Sprintf("identity:%d port:%d proto:%d",
				server.DnsServerIdentity, server.DnsServerPort, server.DnsServerProto))
		}

		policyDetail := fmt.Sprintf("Rule[%d]: Patterns:%v Servers:[%s]",
			i, rule.DnsPattern, strings.Join(servers, ","))
		policyDetails = append(policyDetails, policyDetail)
	}

	return []string{
		p.Identity.String(),
		strings.Join(policyDetails, " | "),
	}
}

var _ statedb.TableWritable = PolicyRules{}

type identityToIPs struct {
	Identity identity.NumericIdentity
	IPs      part.Set[netip.Prefix]
}

// TableHeader implements statedb.TableWritable.
func (i identityToIPs) TableHeader() []string {
	return []string{"Identity", "IPs"}
}

// TableRow implements statedb.TableWritable.
func (i identityToIPs) TableRow() []string {
	ips := make([]string, 0, i.IPs.Len())
	for p := range i.IPs.All() {
		ips = append(ips, p.String())
	}
	return []string{i.Identity.String(), strings.Join(ips, ", ")}
}

var _ statedb.TableWritable = identityToIPs{}

const (
	PolicyRulesTableName   = "sdp-policy-rules"
	IdentityToIPsTableName = "sdp-identity-to-ip"
)

var (
	PolicyRulesIndex = statedb.Index[PolicyRules, identity.NumericIdentity]{
		Name: "id",
		FromObject: func(e PolicyRules) index.KeySet {
			return index.NewKeySet(index.Uint32(e.Identity.Uint32()))
		},
		FromKey: func(key identity.NumericIdentity) index.Key {
			return index.Uint32(key.Uint32())
		},
		FromString: index.Uint32String,
		Unique:     true,
	}
	idIndexIdentityToIP = statedb.Index[identityToIPs, identity.NumericIdentity]{
		Name: "id",
		FromObject: func(e identityToIPs) index.KeySet {
			return index.NewKeySet(index.Uint32(e.Identity.Uint32()))
		},
		FromKey: func(key identity.NumericIdentity) index.Key {
			return index.Uint32(key.Uint32())
		},
		FromString: index.Uint32String,
		Unique:     true,
	}
	kaep = keepalive.EnforcementPolicy{
		PermitWithoutStream: true, // Allow pings even when there are no active streams
	}
	kasp = keepalive.ServerParameters{
		Time:    5 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
		Timeout: 1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
	}
)

// listenConfig is an interface that abstracts the creation of a net.Listener.
type listenConfig interface {
	Listen(ctx context.Context, network, addr string) (net.Listener, error)
}

// defaultListener implements Listener by using net.ListenConfig.
type defaultListener struct{}

func (d *defaultListener) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, network, addr)
}

var _ listenConfig = &defaultListener{}

func newDefaultListener() listenConfig {
	return &defaultListener{}
}

type PolicyUpdater interface {
	// UpdatePolicyRules is used to update the current state of the policy rules at the
	// gRPC server. These rules are sent to the standalone DNS proxy.
	// This is currently being called whenever there is a policy regeneration event
	// for an endpoint.
	UpdatePolicyRules(map[identity.NumericIdentity]policy.SelectorPolicy) error

	// IsEnabled returns true if the standalone DNS proxy is enabled
	IsEnabled() bool
}

var closedWatchChannel = func() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// StreamPolicyState is a bidirectional streaming RPC to subscribe to DNS policies
// SDP calls this method to subscribe to DNS policies
// For each stream, we subscribe to the changes in the policy rules table and identity to IPs mapping.
// The flow of the method is as follows:
//  1. Send the current state of the DNS rules and identity to IPs mapping to the client.
//  2. Subscribe to the changes in the policy rules table and identity to IPs mapping.
//  3. For each change in the policy rules table or identity to IPs mapping, send the current state of the DNS rules and identity to IPs mapping to the client.
//  4. If the stream context is done, return.
func (s *FQDNDataServer) StreamPolicyState(stream pb.FQDNData_StreamPolicyStateServer) error {
	streamCtx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	limiter := rate.NewLimiter(time.Second, 1)
	defer limiter.Stop()

	rulesWatch := closedWatchChannel
	changeWatch := closedWatchChannel
	for {

		select {
		case <-streamCtx.Done():
			return streamCtx.Err()
		case <-rulesWatch:
		case <-changeWatch:
		}
		// If there are changes in the policy rules table or identity to IPs mapping, we will send the current state
		// of the DNS rules and identity to IPs mapping to the client.
		txn := s.db.ReadTxn()
		identityToIPs, watch := s.identityToIPsTable.AllWatch(txn)
		changeWatch = watch
		rules, watch := s.policyRulesTable.AllWatch(txn)
		rulesWatch = watch

		if err := s.sendAndRecvAckForDNSPolicies(stream, rules, identityToIPs); err != nil {
			return err
		}
		// Limit the rate at which we send the full snapshots
		if err := limiter.Wait(streamCtx); err != nil {
			return err
		}
	}

}

// sendAndRecvAckForDNSPolicies sends the current state of the DNS policies to the client
// and waits for the ACK from the client.
// It builds the egress L7 DNS policies with endpoint information based on the identity to IPs mapping.
// There are two main phases in this function:
//  1. Process the identity to IPs mapping and build a map of endpoint IDs to their IPs. This is sent to the client for
//     lookup for the ip to endpoint IDs/endpoint identity mapping while serving the DNS req.
//  2. Process the policy rules and build the egress L7 DNS policies with source endpoint information.
func (s *FQDNDataServer) sendAndRecvAckForDNSPolicies(stream pb.FQDNData_StreamPolicyStateServer, rules iter.Seq2[PolicyRules, statedb.Revision], identityToIPs iter.Seq2[identityToIPs, statedb.Revision]) error {
	requestID := uuid.New().String()

	// Build egress L7 DNS policies with endpoint information
	var egressL7DnsPolicy []*pb.DNSPolicy
	var identityToEndpointMapping []*pb.IdentityToEndpointMapping
	var identityToPrefixMapping []*pb.IdentityToPrefixMapping
	// Process identity to IPs mappings - build both for quick lookup map and endpoint mappings
	identityIPMap := make(map[identity.NumericIdentity][]netip.Prefix)

	for identityIP := range identityToIPs {
		var prefixes []netip.Prefix
		endpointToIPsBytes := make(map[uint64][][]byte) // Group IPs by endpoint ID for this identity
		// Process each IP prefix and group by endpoint ID
		for prefix := range identityIP.IPs.All() {
			prefixes = append(prefixes, prefix)

			ip := prefix.Addr()
			ep := s.endpointsLookup.LookupIP(ip)
			if ep != nil {
				epID := uint64(ep.GetID())
				endpointToIPsBytes[epID] = append(endpointToIPsBytes[epID], ip.AsSlice())
			}
		}

		// Store prefixes for DNS policy processing
		identityIPMap[identityIP.Identity] = prefixes

		// Create EndpointInfo structures to be sent to the client
		var endpointInfos []*pb.EndpointInfo
		for epID, ipBytes := range endpointToIPsBytes {
			endpointInfo := &pb.EndpointInfo{
				Id: epID,
				Ip: ipBytes,
			}
			endpointInfos = append(endpointInfos, endpointInfo)
		}

		// Add identity to prefix mapping
		prefixBytes := make([][]byte, 0, len(prefixes))
		for _, p := range prefixes {
			prefixBin, err := p.MarshalBinary()
			if err != nil {
				return err
			}
			prefixBytes = append(prefixBytes, prefixBin)
		}
		identityToPrefixMapping = append(identityToPrefixMapping, &pb.IdentityToPrefixMapping{
			Identity: identityIP.Identity.Uint32(),
			Prefix:   prefixBytes,
		})

		// Add identity to endpoint mapping if there are endpoint infos
		if len(endpointInfos) > 0 {
			identityToEndpointMapping = append(identityToEndpointMapping, &pb.IdentityToEndpointMapping{
				Identity:     identityIP.Identity.Uint32(),
				EndpointInfo: endpointInfos,
			})
		}
	}

	// Process each policy rule to build DNS policies
	for rule := range rules {
		for _, dnsPolicy := range rule.PolicyRules {
			// Get the IPs associated with this identity
			epIPs := identityIPMap[rule.Identity]

			// Track which endpoint IDs we've already added for this specific DNS policy
			// This prevents duplicates when multiple IPs(ipv4/ipv6) from the same identity point to the same endpoint
			addedEndpoints := make(map[uint32]bool)

			// For each IP, find the corresponding endpoint and create DNS policy
			for _, prefix := range epIPs {
				ip := prefix.Addr()
				ep := s.endpointsLookup.LookupIP(ip)
				if ep == nil {
					// If the endpoint is not found, log a warning
					s.log.Debug("Endpoint not found for IP", logfields.IPAddr, ip)
					continue
				}

				endpointID := uint32(ep.GetID())

				// Skip if we've already added this endpoint for this DNS policy
				if addedEndpoints[endpointID] {
					continue
				}
				// Mark this endpoint as added for this DNS policy
				addedEndpoints[endpointID] = true

				// Create DNS policy with endpoint information
				egressL7DnsPolicy = append(egressL7DnsPolicy, &pb.DNSPolicy{
					SourceEndpointId: endpointID,
					DnsServers:       dnsPolicy.DnsServers,
					DnsPattern:       dnsPolicy.DnsPattern,
				})
			}
		}
	}

	policyState := &pb.PolicyState{
		RequestId:                 requestID,
		EgressL7DnsPolicy:         egressL7DnsPolicy,
		IdentityToEndpointMapping: identityToEndpointMapping,
		IdentityToPrefixMapping:   identityToPrefixMapping,
	}

	if err := stream.Send(policyState); err != nil {
		s.log.Error("Error sending DNS policies to client", logfields.Error, err)
		return err
	}
	response, err := stream.Recv()
	if err != nil {
		s.log.Error("Error receiving DNS policies ACK from client", logfields.Error, err)
		return err
	}

	s.log.Debug("Received DNS policies ACK from client", logfields.Response, response)
	return nil
}

// newPolicyRulesTable creates a new table for storing the policy rules and registers it with the database.
func newPolicyRulesTable(db *statedb.DB) (statedb.RWTable[PolicyRules], error) {
	return statedb.NewTable(
		db,
		PolicyRulesTableName,
		PolicyRulesIndex,
	)
}

// newIdentityToIPsTable creates a new table for storing the identity to IP mapping and registers it with the database.
func newIdentityToIPsTable(db *statedb.DB) (statedb.RWTable[identityToIPs], error) {
	return statedb.NewTable(
		db,
		IdentityToIPsTableName,
		idIndexIdentityToIP,
	)
}

// NewServer creates a new FQDNDataServer which is used to handle the Standalone DNS Proxy grpc service
func NewServer(params serverParams) *FQDNDataServer {

	fqdnDataServer := &FQDNDataServer{
		port:               params.Config.StandaloneDNSProxyServerPort,
		endpointsLookup:    params.EndpointsLookup,
		updateOnDNSMsg:     params.DNSRequestHandler,
		log:                params.Logger,
		prefixLengths:      counter.DefaultPrefixLengthCounter(),
		listener:           params.DefaultListener,
		db:                 params.DB,
		policyRulesTable:   params.PolicyRulesTable,
		identityToIPsTable: params.IdentityToIPsTable,
		enabled:            true,
	}

	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	fqdnDataServer.grpcServer = grpcServer
	pb.RegisterFQDNDataServer(grpcServer, fqdnDataServer)
	return fqdnDataServer
}

// OnIPIdentityCacheChange is a method to receive the IP identity cache change events
func (s *FQDNDataServer) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr types.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8) {
	if cidr.ClusterID() != 0 {
		return
	}

	txn := s.db.WriteTxn(s.identityToIPsTable)
	defer txn.Abort()
	prefix := cidr.AsPrefix()
	if cidr.ClusterID() == 0 {
		switch modType {
		case ipcache.Upsert:
			if oldID != nil {
				// Remove from the old identity
				err := s.deleteFromIdentityToIPLocked(txn, oldID, prefix)
				if err != nil {
					s.log.Error("Failed to delete old identity from identity to IP mapping", logfields.Error, err)
					return
				}
			}

			newObj := identityToIPs{
				Identity: newID.ID,
				IPs:      part.NewSet(prefix),
			}
			_, _, err := s.identityToIPsTable.Modify(txn, newObj, func(oldObj identityToIPs, newObj identityToIPs) identityToIPs {
				// Update the existing record with the new IPs
				newIPs := oldObj.IPs.Union(part.NewSet(prefix))
				return identityToIPs{
					Identity: oldObj.Identity,
					IPs:      newIPs,
				}
			})
			if err != nil {
				s.log.Error("Failed to update identity to IP mapping", logfields.Error, err)
				return
			}
			s.prefixLengths.Add([]netip.Prefix{prefix})
		case ipcache.Delete:
			if oldID != nil {
				err := s.deleteFromIdentityToIPLocked(txn, oldID, prefix)
				if err != nil {
					s.log.Error("Failed to delete identity from identity to IP mapping", logfields.Error, err)
					return
				}
			}
		}
	}
	txn.Commit()
}

// deleteFromIdentityToIPLocked deletes the given IP from the identity to IP mapping
// It is called when the IP identity cache changes and the IP is deleted from the mapping
// It is also called when the IP is upserted with a new identity
// It removes the prefix from the prefixLengths map
// It is called with the identityToIpMutex lock held
func (s *FQDNDataServer) deleteFromIdentityToIPLocked(txn statedb.WriteTxn, identity *ipcache.Identity, prefix netip.Prefix) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	existing, _, found := s.identityToIPsTable.Get(txn, idIndexIdentityToIP.Query(identity.ID))
	if !found {
		return fmt.Errorf("identity %d not found in identity to IP mapping", identity.ID.Uint32())
	}

	newIPs := existing.IPs.Delete(prefix)
	if existing.IPs.Has(prefix) {
		// If the prefix was found, we need to remove it from the prefixLength
		s.prefixLengths.Delete([]netip.Prefix{prefix})
	}

	if newIPs.Len() == 0 {
		// If no IPs remain, delete the record.
		_, _, err := s.identityToIPsTable.Delete(txn, existing)
		if err != nil {
			return fmt.Errorf("failed to delete identity to IP mapping: %w", err)
		}
	} else {
		// Update the record with the new IP list.
		_, _, err := s.identityToIPsTable.Insert(txn, identityToIPs{
			Identity: identity.ID,
			IPs:      newIPs,
		})
		if err != nil {
			return fmt.Errorf("failed to insert identity to IP mapping: %w", err)
		}
	}
	return nil
}

// UpdatePolicyRules updates the current state of the DNS rules with the given policies in the policy rules table.
// This method is called when the DNS rules are updated during the endpoint regeneration, we store the state of the DNS rules.
func (s *FQDNDataServer) UpdatePolicyRules(policies map[identity.NumericIdentity]policy.SelectorPolicy) error {
	wtxn := s.db.WriteTxn(s.policyRulesTable)
	defer wtxn.Abort()

	for secID, selectorPolicy := range policies {
		dnsPolicies, err := s.buildDNSPoliciesForIdentity(selectorPolicy)
		if err != nil {
			return fmt.Errorf("failed to build DNS policies for identity %d: %w", secID, err)
		}

		if len(dnsPolicies) == 0 {
			// If no DNS policies found, delete the policy rules for this identity
			// since we are getting the snapshot of the policies.
			if err := s.deletePolicyRules(wtxn, secID); err != nil {
				return fmt.Errorf("failed to delete policy rules for identity %d: %w", secID, err)
			}
		} else {
			// Insert/update policy rules for this identity
			if err := s.insertPolicyRules(wtxn, secID, dnsPolicies); err != nil {
				return fmt.Errorf("failed to insert policy rules for identity %d: %w", secID, err)
			}
		}
	}

	wtxn.Commit()
	return nil
}

func (s *FQDNDataServer) IsEnabled() bool {
	return s != nil && s.enabled
}

// buildDNSPoliciesForIdentity extracts DNS policies from a selector policy
func (s *FQDNDataServer) buildDNSPoliciesForIdentity(selectorPolicy policy.SelectorPolicy) ([]*pb.DNSPolicy, error) {
	dnsPolicies := make([]*pb.DNSPolicy, 0)

	if selectorPolicy == nil {
		return dnsPolicies, nil
	}

	for l4Filter, policyTuple := range selectorPolicy.RedirectFilters() {
		if !s.isDNSPolicy(policyTuple.Policy) {
			continue
		}
		dnsPolicy := s.buildDNSPolicyFromL4Filter(l4Filter, policyTuple)
		if dnsPolicy == nil {
			return nil, fmt.Errorf("failed to build DNS policy from L4 filter")
		}

		dnsPolicies = append(dnsPolicies, dnsPolicy)
	}

	return dnsPolicies, nil
}

// isDNSPolicy checks if the given policy is a DNS policy
func (s *FQDNDataServer) isDNSPolicy(psp *policy.PerSelectorPolicy) bool {
	return psp != nil && psp.L7Parser == policy.ParserTypeDNS
}

// buildDNSPolicyFromL4Filter creates a DNS policy from L4 filter and policy tuple
func (s *FQDNDataServer) buildDNSPolicyFromL4Filter(l4Filter *policy.L4Filter, policyTuple policy.PerSelectorPolicyTuple) *pb.DNSPolicy {
	dnsServers := s.buildDNSServers(l4Filter, policyTuple.Selector)
	dnsPatterns := s.extractDNSPatterns(policyTuple.Policy)

	return &pb.DNSPolicy{
		DnsServers: dnsServers,
		DnsPattern: dnsPatterns,
	}
}

// buildDNSServers creates the list of DNS servers from L4 filter and cache selector
func (s *FQDNDataServer) buildDNSServers(l4Filter *policy.L4Filter, cacheSelector policy.CachedSelector) []*pb.DNSServer {
	if cacheSelector == nil || len(cacheSelector.GetSelections()) == 0 {
		// No cache selector - return single server without identity
		return []*pb.DNSServer{
			{
				DnsServerPort:  uint32(l4Filter.GetPort()),
				DnsServerProto: uint32(l4Filter.U8Proto),
			},
		}
	}
	selections := cacheSelector.GetSelections()
	dnsServers := make([]*pb.DNSServer, 0, len(selections))

	for _, selection := range selections {
		server := &pb.DNSServer{
			DnsServerIdentity: selection.Uint32(),
			DnsServerPort:     uint32(l4Filter.GetPort()),
			DnsServerProto:    uint32(l4Filter.U8Proto),
		}
		dnsServers = append(dnsServers, server)
	}
	return dnsServers
}

// extractDNSPatterns extracts DNS patterns from the policy DNS rules
func (s *FQDNDataServer) extractDNSPatterns(selectorPolicy *policy.PerSelectorPolicy) []string {
	var patterns []string
	if selectorPolicy == nil || selectorPolicy.DNS == nil {
		return patterns
	}

	for _, dnsRule := range selectorPolicy.DNS {
		if dnsRule.MatchPattern != "" {
			patterns = append(patterns, dnsRule.MatchPattern)
		}
		if dnsRule.MatchName != "" {
			patterns = append(patterns, dnsRule.MatchName)
		}
	}

	return patterns
}

// insertPolicyRules inserts the policy rules into the database
func (s *FQDNDataServer) insertPolicyRules(writeTxn statedb.WriteTxn, secID identity.NumericIdentity, dnsPolicies []*pb.DNSPolicy) error {
	rules := PolicyRules{
		Identity:    secID,
		PolicyRules: dnsPolicies,
	}

	_, _, err := s.policyRulesTable.Insert(writeTxn, rules)
	return err
}

// deletePolicyRules deletes the policy rules for the given identity from the database
func (s *FQDNDataServer) deletePolicyRules(writeTxn statedb.WriteTxn, secID identity.NumericIdentity) error {
	existing, _, found := s.policyRulesTable.Get(writeTxn, PolicyRulesIndex.Query(secID))
	if !found {
		// Identity not found in table, nothing to delete
		s.log.Debug("Policy rules not found for identity, skipping deletion", logfields.Identity, secID.Uint32())
		return nil
	}

	_, _, err := s.policyRulesTable.Delete(writeTxn, existing)
	if err != nil {
		return fmt.Errorf("failed to delete policy rules: %w", err)
	}

	s.log.Debug("Deleted policy rules for identity", logfields.Identity, secID.Uint32())
	return nil
}

// UpdateMappingRequest updates the FQDN mapping with the given data
// SDP sends the fqdn mapping to cilium agent
// Steps to update the mapping:
// 1. Get the endpoint from the IP
// 2. If the endpoint is not found, return an error
// 3. If the IPs are not empty, update the cilium agent with the mapping
// Note: Not all metrics are reported by the standalone dns proxy yet and will be added in the future.
func (s *FQDNDataServer) UpdateMappingRequest(ctx context.Context, mappings *pb.FQDNMapping) (*pb.UpdateMappingResponse, error) {
	now := time.Now()
	var ips []netip.Addr
	stat := dnsproxy.ProxyRequestContext{DataSource: accesslog.DNSSourceStandaloneProxy}

	sourceIP := mappings.GetSourceIp()
	if sourceIP == nil {
		s.log.Error("Source IP is nil in FQDN mapping")
		return &pb.UpdateMappingResponse{
			Response: pb.ResponseCode_RESPONSE_CODE_ERROR_INVALID_ARGUMENT,
		}, fmt.Errorf("source IP is nil in FQDN mapping")
	}

	endpointAddr := netip.MustParseAddr(string(sourceIP))
	ep := s.endpointsLookup.LookupIP(endpointAddr)
	if ep == nil {
		s.log.Error("Endpoint not found for IP", logfields.IPAddr, endpointAddr)
		return &pb.UpdateMappingResponse{
			Response: pb.ResponseCode_RESPONSE_CODE_ERROR_ENDPOINT_NOT_FOUND,
		}, fmt.Errorf("endpoint not found for IP: %s", mappings.SourceIp)
	}

	recordIps := mappings.GetRecordIp()
	if len(recordIps) == 0 {
		return &pb.UpdateMappingResponse{
			Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
		}, nil
	}

	for _, ip := range recordIps {
		ips = append(ips, netip.MustParseAddr(string(ip)))
	}

	if len(mappings.GetFqdn()) == 0 {
		s.log.Error("FQDN is nil or empty in FQDN mapping")
		return &pb.UpdateMappingResponse{
			Response: pb.ResponseCode_RESPONSE_CODE_ERROR_INVALID_ARGUMENT,
		}, fmt.Errorf("FQDN is nil or empty in FQDN mapping")
	}

	if mappings.GetResponseCode() == dns.RcodeSuccess {
		s.updateOnDNSMsg.UpdateOnDNSMsg(now, ep, mappings.GetFqdn(), ips, int(mappings.GetTtl()), &stat)
	}

	return &pb.UpdateMappingResponse{
		Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
	}, nil
}

// ListenAndServe starts the Standalone DNS Proxy gRPC server on the given port
func (s *FQDNDataServer) ListenAndServe(ctx context.Context, health cell.Health) error {
	listenErrs := make(chan error)
	go func() {
		defer close(listenErrs)

		address := fmt.Sprintf("localhost:%d", s.port)
		s.log.Info("Starting Standalone DNS Proxy server on", logfields.Address, address)
		lis, err := s.listener.Listen(ctx, "tcp", address)
		if err != nil {
			s.log.Error("Failed to listen", logfields.Error, err)
			listenErrs <- err
			return
		}

		if err := s.grpcServer.Serve(lis); err != nil {
			s.log.Error("Failed to serve the standalone DNS Proxy gRPC server", logfields.Error, err)
			listenErrs <- err

		}
	}()

	health.OK(fmt.Sprintf("Serving at %d", s.port))

	select {
	case err := <-listenErrs:
		return err
	case <-ctx.Done():
		s.Stop()
		<-listenErrs
		return nil
	}
}

func (s *FQDNDataServer) Stop() {
	if s.grpcServer == nil {
		return
	}

	// Stop the grpc server
	s.grpcServer.GracefulStop()
}

func init() {
	part.RegisterKeyType(
		func(prefix netip.Prefix) []byte { return []byte(prefix.String()) })
}
