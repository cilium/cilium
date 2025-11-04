// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

const (
	DNSRulesTableName     = "sdp-dns-rules"
	IPtoIdentityTableName = "sdp-ip-to-identity"
)

func DNSRulesCompositeKey(epID uint32, pp restore.PortProto) uint64 {
	return (uint64(epID) << 32) | uint64(pp)
}

type DNSRules struct {
	EndpointID uint32
	PortProto  restore.PortProto
	DNSRule    policy.L7DataMap
}

type IPtoIdentity struct {
	IP       netip.Addr
	Identity identity.NumericIdentity
}

var (
	DNSRulesIndex = statedb.Index[DNSRules, uint64]{
		Name: "id",
		FromObject: func(e DNSRules) index.KeySet {
			return index.NewKeySet(index.Uint64(DNSRulesCompositeKey(e.EndpointID, e.PortProto)))
		},
		FromKey: func(key uint64) index.Key {
			return index.Uint64(key)
		},
		FromString: index.Uint64String,
		Unique:     true,
	}

	idIPToIdentityIndex = statedb.Index[IPtoIdentity, netip.Addr]{
		Name: "ip",
		FromObject: func(e IPtoIdentity) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(e.IP))
		},
		FromKey: func(key netip.Addr) index.Key {
			return index.NetIPAddr(key)
		},
		FromString: index.NetIPAddrString,
		Unique:     true,
	}
)

// TableHeader implements statedb.TableWritable.
func (p DNSRules) TableHeader() []string {
	return []string{"EndpointID", "PortProto", "DNS Rules"}
}

// TableRow implements statedb.TableWritable.
func (p DNSRules) TableRow() []string {
	var dnsRules string
	for _, sel := range p.DNSRule {
		if sel != nil && sel.L7Rules.DNS != nil {
			dnsRules += fmt.Sprintf("%v|", sel.L7Rules.DNS)
		}

	}
	return []string{
		fmt.Sprintf("%d", p.EndpointID),
		p.PortProto.String(),
		dnsRules,
	}
}

func (i IPtoIdentity) TableHeader() []string {
	return []string{
		"IP",
		"Identity",
	}
}

func (i IPtoIdentity) TableRow() []string {
	return []string{
		i.IP.String(),
		fmt.Sprintf("%d", i.Identity.Uint32()),
	}
}

// ConnectionHandler defines the interface for standalone DNS proxy connection handler
type ConnectionHandler interface {
	// StartConnection starts the gRPC connection through a hive/job
	// It is responsible for establishing the connection with the Cilium agent.
	// This method is called when the standalone DNS proxy starts.
	StartConnection()

	// StopConnection stops the gRPC connection and removes all hive/job
	// It is responsible for closing the connection with the Cilium agent.
	StopConnection()

	// NotifyOnMsg notifies the gRPC client about DNS messages received by the standalone DNS proxy
	// This method is called by the DNS proxy when it receives a DNS message.
	// It is responsible for sending the DNS message to the Cilium agent for further processing.
	// Note: This method is intentionally left empty for now. And will be implemented in future PRs.
	NotifyOnMsg(msg *pb.FQDNMapping) error
}

// GRPCClient  is a gRPC connection handler for standalone DNS proxy communication with Cilium agent
type GRPCClient struct {
	logger *slog.Logger

	db            *statedb.DB
	dnsRulesTable statedb.RWTable[DNSRules]
}

// createGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func createGRPCClient(logger *slog.Logger, db *statedb.DB, dnsRulesTable statedb.RWTable[DNSRules]) *GRPCClient {
	return &GRPCClient{
		logger:        logger,
		db:            db,
		dnsRulesTable: dnsRulesTable,
	}
}

func (c *GRPCClient) StartConnection() {
	c.logger.Info("Starting gRPC connection for standalone DNS proxy")
	// Here we would typically start the gRPC connection to the Cilium agent.
	// This is a placeholder for the actual implementation.

	// Adding a dummy call to updatePolicyState to avoid unused method warning.
	c.updatePolicyState(&pb.PolicyState{})
}

func (c *GRPCClient) StopConnection() {
}

// Note: This method is intentionally left empty for now. Will be implemented in future PRs.
func (c *GRPCClient) NotifyOnMsg(msg *pb.FQDNMapping) error {
	c.logger.Info("DNS message received")
	return nil
}

// newDNSRulesTable creates a new table for storing the DNS rules and registers it with the database.
// This table will be used to store the DNS rules for the standalone DNS proxy.
// The standalone DNS proxy will use this table to retrieve the DNS rules and update the DNS proxy with the
// latest rules received from the Cilium agent.
func newDNSRulesTable(db *statedb.DB) (statedb.RWTable[DNSRules], error) {
	return statedb.NewTable(
		db,
		DNSRulesTableName,
		DNSRulesIndex,
	)
}

// newIPtoIdentityTable creates a new table for storing the IP to identity mappings.
func newIPtoIdentityTable(db *statedb.DB) (statedb.RWTable[IPtoIdentity], error) {
	return statedb.NewTable(
		db,
		IPtoIdentityTableName,
		idIPToIdentityIndex,
	)
}

// updatePolicyState processes the received PolicyState message and updates the DNSRules/IPToIdentity table accordingly.
func (c *GRPCClient) updatePolicyState(state *pb.PolicyState) error {
	err := c.updateDNSRules(state.GetEgressL7DnsPolicy())
	if err != nil {
		return err
	}
	return nil
}

// updateDNSRules updates the DNS rules table with the received DNS policies.
func (c *GRPCClient) updateDNSRules(rules []*pb.DNSPolicy) error {
	wtxn := c.db.WriteTxn(c.dnsRulesTable)
	defer wtxn.Abort()

	// Clear existing entries as we are replacing the entire mapping with the given snapshot.
	err := c.dnsRulesTable.DeleteAll(wtxn)
	if err != nil {
		c.logger.Error("Failed to clear existing DNS rules", logfields.Error, err)
		return err
	}

	// create a mapping of endpointID to PortProto to L7DataMap, similar to what DNS proxy expects
	endpointIdToRule := make(map[uint32]map[restore.PortProto]policy.L7DataMap)
	for _, rule := range rules {
		portProtoToServerIdentity := make(map[restore.PortProto]identity.NumericIdentitySlice)
		for _, dnsServer := range rule.GetDnsServers() {
			pp := restore.MakeV2PortProto(uint16(dnsServer.GetDnsServerPort()), u8proto.U8proto(dnsServer.GetDnsServerProto()))
			portProtoToServerIdentity[pp] = append(portProtoToServerIdentity[pp], identity.NumericIdentity(dnsServer.GetDnsServerIdentity()))
		}

		portProtoToDNSrules := make(map[restore.PortProto]policy.L7DataMap)
		for portProto, identities := range portProtoToServerIdentity {
			dnsRulesSlice := make([]api.PortRuleDNS, 0, len(rule.GetDnsPattern()))
			for _, pat := range rule.GetDnsPattern() {
				dnsRulesSlice = append(dnsRulesSlice, api.PortRuleDNS{
					MatchPattern: pat,
				})
			}
			cs := make(policy.L7DataMap)
			if len(dnsRulesSlice) == 0 {
				cs[&DNSServerIdentity{Identities: identities}] = nil

			} else {
				cs[&DNSServerIdentity{Identities: identities}] = &policy.PerSelectorPolicy{
					L7Rules: api.L7Rules{
						DNS: dnsRulesSlice,
					},
				}
			}
			portProtoToDNSrules[portProto] = cs
		}
		// Process each DNS policy rule
		epId := rule.GetSourceEndpointId()
		if _, ok := endpointIdToRule[epId]; !ok {
			endpointIdToRule[epId] = make(map[restore.PortProto]policy.L7DataMap)
		}

		for portProto, cs := range portProtoToDNSrules {
			if _, ok := endpointIdToRule[epId][portProto]; !ok {
				endpointIdToRule[epId][portProto] = make(policy.L7DataMap)
			}

			maps.Copy(endpointIdToRule[epId][portProto], cs)
		}
	}

	for epId, portProtoToRules := range endpointIdToRule {
		for portProto, rules := range portProtoToRules {
			dnsRule := DNSRules{
				EndpointID: epId,
				PortProto:  portProto,
				DNSRule:    rules,
			}
			if _, _, err := c.dnsRulesTable.Insert(wtxn, dnsRule); err != nil {
				c.logger.Error("Failed to insert DNS rule into table", logfields.Error, err)
				return err
			}
		}
	}
	wtxn.Commit()

	return nil
}

// DNSServerIdentity contains the identities of the DNS servers and used to
// determine if a DNS request is allowed or not from standalone DNS proxy.
// It adheres the interface policy.CachedSelector and reuses the
// in agent dns proxy filtering path.
type DNSServerIdentity struct {
	Identities identity.NumericIdentitySlice
}

func (d *DNSServerIdentity) Selects(identity identity.NumericIdentity) bool {
	return slices.Contains(d.Identities, identity)
}

func (d *DNSServerIdentity) String() string {
	identityStrings := make([]string, len(d.Identities))
	for i, id := range d.Identities {
		identityStrings[i] = strconv.FormatUint(uint64(id), 10)
	}
	return strings.Join(identityStrings, ",")
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) IsWildcard() bool {
	return false
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) IsNone() bool {
	return false
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) GetSelections() identity.NumericIdentitySlice {
	return d.Identities
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) GetSelectionsAt(types.SelectorReadTxn) identity.NumericIdentitySlice {
	return d.Identities
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) GetMetadataLabels() labels.LabelArray {
	return nil
}
