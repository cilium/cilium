// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cespare/xxhash/v2"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"
	"go.yaml.in/yaml/v3"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/cache"
	"github.com/cilium/cilium/pkg/hive"
)

// InitWaitFunc is provided by the load-balancing cell to wait until the
// load-balancing control-plane has finished reconciliation of the initial
// data set.
type InitWaitFunc hive.WaitFunc

type IPFamily = bool

const (
	IPFamilyIPv4 = IPFamily(false)
	IPFamilyIPv6 = IPFamily(true)
)

// SVCType is a type of a service.
type SVCType string

const (
	SVCTypeNone          = SVCType("NONE")
	SVCTypeHostPort      = SVCType("HostPort")
	SVCTypeClusterIP     = SVCType("ClusterIP")
	SVCTypeNodePort      = SVCType("NodePort")
	SVCTypeExternalIPs   = SVCType("ExternalIPs")
	SVCTypeLoadBalancer  = SVCType("LoadBalancer")
	SVCTypeLocalRedirect = SVCType("LocalRedirect")
)

// SVCTrafficPolicy defines which backends are chosen
type SVCTrafficPolicy string

const (
	SVCTrafficPolicyNone    = SVCTrafficPolicy("NONE")
	SVCTrafficPolicyCluster = SVCTrafficPolicy("Cluster")
	SVCTrafficPolicyLocal   = SVCTrafficPolicy("Local")
)

// SVCNatPolicy defines whether we need NAT46/64 translation for backends
type SVCNatPolicy string

const (
	SVCNatPolicyNone  = SVCNatPolicy("NONE")
	SVCNatPolicyNat46 = SVCNatPolicy("Nat46")
	SVCNatPolicyNat64 = SVCNatPolicy("Nat64")
)

type SVCForwardingMode string

const (
	SVCForwardingModeUndef = SVCForwardingMode("")
	SVCForwardingModeDSR   = SVCForwardingMode("dsr")
	SVCForwardingModeSNAT  = SVCForwardingMode("snat")
)

func ToSVCForwardingMode(s string) SVCForwardingMode {
	switch s {
	case LBModeDSR:
		return SVCForwardingModeDSR
	case LBModeSNAT:
		return SVCForwardingModeSNAT
	default:
		return SVCForwardingModeUndef
	}
}

type SVCLoadBalancingAlgorithm uint8

const (
	SVCLoadBalancingAlgorithmUndef  SVCLoadBalancingAlgorithm = 0
	SVCLoadBalancingAlgorithmRandom SVCLoadBalancingAlgorithm = 1
	SVCLoadBalancingAlgorithmMaglev SVCLoadBalancingAlgorithm = 2
)

func (d SVCLoadBalancingAlgorithm) String() string {
	switch d {
	case SVCLoadBalancingAlgorithmRandom:
		return "random"
	case SVCLoadBalancingAlgorithmMaglev:
		return "maglev"
	default:
		return "undef"
	}
}

func ToSVCLoadBalancingAlgorithm(s string) SVCLoadBalancingAlgorithm {
	if s == LBAlgorithmMaglev {
		return SVCLoadBalancingAlgorithmMaglev
	}
	if s == LBAlgorithmRandom {
		return SVCLoadBalancingAlgorithmRandom
	}
	return SVCLoadBalancingAlgorithmUndef
}

type SVCSourceRangesPolicy string

const (
	SVCSourceRangesPolicyAllow = SVCSourceRangesPolicy("allow")
	SVCSourceRangesPolicyDeny  = SVCSourceRangesPolicy("deny")
)

type SVCProxyDelegation string

const (
	SVCProxyDelegationNone            = SVCProxyDelegation("none")
	SVCProxyDelegationDelegateIfLocal = SVCProxyDelegation("delegate-if-local")
)

// ServiceFlags is the datapath representation of the service flags that can be
// used (lb{4,6}_service.flags)
type ServiceFlags uint16

const (
	serviceFlagNone            = 0
	serviceFlagExternalIPs     = 1 << 0
	serviceFlagNodePort        = 1 << 1
	serviceFlagExtLocalScope   = 1 << 2
	serviceFlagHostPort        = 1 << 3
	serviceFlagSessionAffinity = 1 << 4
	serviceFlagLoadBalancer    = 1 << 5
	serviceFlagRoutable        = 1 << 6
	serviceFlagSourceRange     = 1 << 7
	serviceFlagLocalRedirect   = 1 << 8
	serviceFlagNat46x64        = 1 << 9
	serviceFlagL7LoadBalancer  = 1 << 10
	serviceFlagLoopback        = 1 << 11
	serviceFlagIntLocalScope   = 1 << 12
	serviceFlagTwoScopes       = 1 << 13
	serviceFlagQuarantined     = 1 << 14
	// serviceFlagSrcRangesDeny is set on master
	// svc entry, serviceFlagQuarantined is only
	// set on backend svc entries.
	serviceFlagSourceRangeDeny = 1 << 14
	serviceFlagFwdModeDSR      = 1 << 15
)

// +k8s:deepcopy-gen=true
type SvcFlagParam struct {
	SvcType          SVCType
	SvcNatPolicy     SVCNatPolicy
	SvcFwdModeDSR    bool
	SvcExtLocal      bool
	SvcIntLocal      bool
	SessionAffinity  bool
	IsRoutable       bool
	CheckSourceRange bool
	SourceRangeDeny  bool
	L7LoadBalancer   bool
	LoopbackHostport bool
	Quarantined      bool
}

// NewSvcFlag creates service flag
func NewSvcFlag(p *SvcFlagParam) ServiceFlags {
	var flags ServiceFlags

	switch p.SvcType {
	case SVCTypeExternalIPs:
		flags |= serviceFlagExternalIPs
	case SVCTypeNodePort:
		flags |= serviceFlagNodePort
	case SVCTypeLoadBalancer:
		flags |= serviceFlagLoadBalancer
	case SVCTypeHostPort:
		flags |= serviceFlagHostPort
	case SVCTypeLocalRedirect:
		flags |= serviceFlagLocalRedirect
	}

	switch p.SvcNatPolicy {
	case SVCNatPolicyNat46:
		fallthrough
	case SVCNatPolicyNat64:
		flags |= serviceFlagNat46x64
	}

	if p.SvcExtLocal {
		flags |= serviceFlagExtLocalScope
	}
	if p.SvcIntLocal {
		flags |= serviceFlagIntLocalScope
	}
	if p.SessionAffinity {
		flags |= serviceFlagSessionAffinity
	}
	if p.IsRoutable {
		flags |= serviceFlagRoutable
	}
	if p.SourceRangeDeny {
		flags |= serviceFlagSourceRangeDeny
	}
	if p.CheckSourceRange {
		flags |= serviceFlagSourceRange
	}
	if p.L7LoadBalancer {
		flags |= serviceFlagL7LoadBalancer
	}
	if p.SvcExtLocal != p.SvcIntLocal && p.SvcType != SVCTypeClusterIP {
		flags |= serviceFlagTwoScopes
	}
	if p.Quarantined {
		flags |= serviceFlagQuarantined
	}
	if p.SvcFwdModeDSR {
		flags |= serviceFlagFwdModeDSR
	}
	if p.LoopbackHostport {
		flags |= serviceFlagLoopback
	}

	return flags
}

// SVCType returns a service type from the flags
func (s ServiceFlags) SVCType() SVCType {
	switch {
	case s&serviceFlagExternalIPs != 0:
		return SVCTypeExternalIPs
	case s&serviceFlagNodePort != 0:
		return SVCTypeNodePort
	case s&serviceFlagLoadBalancer != 0:
		return SVCTypeLoadBalancer
	case s&serviceFlagHostPort != 0:
		return SVCTypeHostPort
	case s&serviceFlagLocalRedirect != 0:
		return SVCTypeLocalRedirect
	default:
		return SVCTypeClusterIP
	}
}

func (s ServiceFlags) IsL7LB() bool {
	return s&serviceFlagL7LoadBalancer != 0
}

// SVCExtTrafficPolicy returns a service traffic policy from the flags
func (s ServiceFlags) SVCExtTrafficPolicy() SVCTrafficPolicy {
	switch {
	case s&serviceFlagExtLocalScope != 0:
		return SVCTrafficPolicyLocal
	default:
		return SVCTrafficPolicyCluster
	}
}

// SVCIntTrafficPolicy returns a service traffic policy from the flags
func (s ServiceFlags) SVCIntTrafficPolicy() SVCTrafficPolicy {
	switch {
	case s&serviceFlagIntLocalScope != 0:
		return SVCTrafficPolicyLocal
	default:
		return SVCTrafficPolicyCluster
	}
}

// SVCNatPolicy returns a service NAT policy from the flags
func (s ServiceFlags) SVCNatPolicy(fe L3n4Addr) SVCNatPolicy {
	if s&serviceFlagNat46x64 == 0 {
		return SVCNatPolicyNone
	}

	if fe.IsIPv6() {
		return SVCNatPolicyNat64
	} else {
		return SVCNatPolicyNat46
	}
}

// SVCSlotQuarantined
func (s ServiceFlags) SVCSlotQuarantined() bool {
	if s&serviceFlagQuarantined == 0 {
		return false
	} else {
		return true
	}
}

// String returns the string implementation of ServiceFlags.
func (s ServiceFlags) String() string {
	var str []string
	seenDeny := false

	str = append(str, string(s.SVCType()))
	if s&serviceFlagExtLocalScope != 0 {
		str = append(str, string(SVCTrafficPolicyLocal))
	}
	if s&serviceFlagIntLocalScope != 0 {
		str = append(str, "Internal"+string(SVCTrafficPolicyLocal))
	}
	if s&serviceFlagTwoScopes != 0 {
		str = append(str, "two-scopes")
	}
	if s&serviceFlagSessionAffinity != 0 {
		str = append(str, "sessionAffinity")
	}
	if s&serviceFlagRoutable == 0 {
		str = append(str, "non-routable")
	}
	if s&serviceFlagSourceRange != 0 {
		str = append(str, "check source-range")
		if s&serviceFlagSourceRangeDeny != 0 {
			seenDeny = true
			str = append(str, "deny")
		}
	}
	if s&serviceFlagNat46x64 != 0 {
		str = append(str, "46x64")
	}
	if s&serviceFlagL7LoadBalancer != 0 {
		str = append(str, "l7-load-balancer")
	}
	if s&serviceFlagLoopback != 0 {
		if s.SVCType() == SVCTypeHostPort {
			str = append(str, "loopback")
		} else {
			str = append(str, "delegate-if-local")
		}
	}
	if !seenDeny && s&serviceFlagQuarantined != 0 {
		str = append(str, "quarantined")
	}
	if s&serviceFlagFwdModeDSR != 0 {
		str = append(str, "dsr")
	}
	return strings.Join(str, ", ")
}

// UInt8 returns the UInt16 representation of the ServiceFlags.
func (s ServiceFlags) UInt16() uint16 {
	return uint16(s)
}

const (
	// NONE type.
	NONE = L4Type("NONE")
	// ANY type.
	ANY = L4Type("ANY")
	// TCP type.
	TCP = L4Type("TCP")
	// UDP type.
	UDP = L4Type("UDP")
	// SCTP type.
	SCTP = L4Type("SCTP")
)

const (
	// ScopeExternal is the lookup scope for services from outside the node.
	ScopeExternal uint8 = iota
	// ScopeInternal is the lookup scope for services from inside the node.
	ScopeInternal
)

// BackendState tracks backend's ability to load-balance service traffic.
//
// Valid transition states for a backend -
// BackendStateActive -> BackendStateTerminating, BackendStateQuarantined, BackendStateMaintenance
// BackendStateTerminating -> No valid state transition
// BackendStateQuarantined -> BackendStateActive, BackendStateTerminating
// BackendStateMaintenance -> BackendStateActive
//
// Sources setting the states -
// BackendStateActive - Kubernetes events, service API
// BackendStateTerminating - Kubernetes events
// BackendStateQuarantined - service API
// BackendStateMaintenance - service API
const (
	// BackendStateActive refers to the backend state when it's available for
	// load-balancing traffic. It's the default state for a backend.
	// Backends in this state can be health-checked.
	BackendStateActive BackendState = iota
	// BackendStateTerminating refers to the terminating backend state so that
	// it can be gracefully removed.
	// Backends in this state won't be health-checked.
	BackendStateTerminating
	// BackendStateQuarantined refers to the backend state when it's unreachable,
	// and will not be selected for load-balancing traffic.
	// Backends in this state can be health-checked.
	BackendStateQuarantined
	// BackendStateMaintenance refers to the backend state where the backend
	// is put under maintenance, and will neither be selected for load-balancing
	// traffic nor be health-checked.
	BackendStateMaintenance
	// BackendStateInvalid is an invalid state, and is used to report error conditions.
	// Keep this as the last entry.
	BackendStateInvalid
)

// BackendStateFlags is the datapath representation of the backend flags that
// are used in (lb{4,6}_backend.flags) to store backend state.
type BackendStateFlags = uint8

const (
	BackendStateActiveFlag = iota
	BackendStateTerminatingFlag
	BackendStateQuarantinedFlag
	BackendStateMaintenanceFlag
)

func NewBackendFlags(state BackendState) BackendStateFlags {
	var flags BackendStateFlags

	switch state {
	case BackendStateActive:
		flags = BackendStateActiveFlag
	case BackendStateTerminating:
		flags = BackendStateTerminatingFlag
	case BackendStateQuarantined:
		flags = BackendStateQuarantinedFlag
	case BackendStateMaintenance:
		flags = BackendStateMaintenanceFlag
	}

	return flags
}

func GetBackendStateFromFlags(flags uint8) BackendState {
	switch flags {
	case BackendStateTerminatingFlag:
		return BackendStateTerminating
	case BackendStateQuarantinedFlag:
		return BackendStateQuarantined
	case BackendStateMaintenanceFlag:
		return BackendStateMaintenance
	default:
		return BackendStateActive
	}
}

// DefaultBackendWeight is used when backend weight is not set in ServiceSpec
const DefaultBackendWeight = 100

// AllProtocols is the list of all supported L4 protocols
var AllProtocols = []L4Type{TCP, UDP, SCTP}

// L4Type name.
type L4Type = string

func L4TypeAsByte(l4 L4Type) byte {
	switch l4 {
	case TCP:
		return 'T'
	case UDP:
		return 'U'
	case SCTP:
		return 'S'
	default:
		return '?'
	}
}

// FEPortName is the name of the frontend's port.
type FEPortName string

// ServiceID is the service's ID.
type ServiceID uint16

// ServiceName represents the fully-qualified reference to the service by name,
// including both the namespace and name of the service (and optionally the cluster).
// +k8s:deepcopy-gen=true
type ServiceName struct {
	// str is (<cluster>/)<namespace>/<name>
	str string

	// namePos is where the name starts
	// (<cluster>/)<namespace>/<name>
	//                         ^
	namePos uint16

	// clusterEndPos is where the cluster (including '/' ends. If zero then there is
	// no cluster.
	// (<cluster>/)<namespace>/<name>
	//             ^
	clusterEndPos uint16
}

func (s ServiceName) Cluster() string {
	if s.clusterEndPos > 0 {
		return s.str[:s.clusterEndPos-1]
	}
	return ""
}

func (s ServiceName) Name() string {
	return s.str[s.namePos:]
}

func (s ServiceName) Namespace() string {
	return s.str[s.clusterEndPos : s.namePos-1]
}

func (n ServiceName) Key() index.Key {
	// index.Key is never mutated so it's safe to return the underlying
	// string as []byte without copying.
	return unsafe.Slice(unsafe.StringData(n.str), len(n.str))
}

func NewServiceName(namespace, name string) ServiceName {
	return NewServiceNameInCluster("", namespace, name)
}

// serviceNameCache for deduplicating the [ServiceName.str] to reduce overall
// memory usage.
var serviceNameCache = cache.New(
	func(n ServiceName) uint64 {
		return serviceNameHash(n.Cluster(), n.Namespace(), n.Name())
	},
	nil,
	func(a, b ServiceName) bool {
		return b.str != "" /* only match if non-zero value */ &&
			a.str == b.str
	},
)

func serviceNameHash(cluster, namespace, name string) uint64 {
	var d xxhash.Digest
	d.WriteString(cluster)
	d.WriteString(namespace)
	d.WriteString(name)
	return d.Sum64()
}

func NewServiceNameInCluster(cluster, namespace, name string) ServiceName {
	return cache.GetOrPutWith(
		serviceNameCache,
		serviceNameHash(cluster, namespace, name),
		func(sn ServiceName) bool {
			return len(sn.str) > 0 &&
				sn.Cluster() == cluster && sn.Namespace() == namespace && sn.Name() == name
		},
		func() ServiceName {
			// ServiceName not found from cache, create it.
			var b strings.Builder
			pos := 0
			if cluster != "" {
				n, _ := b.WriteString(cluster)
				b.WriteRune('/')
				pos += n + 1
			}
			cendPos := pos
			n, _ := b.WriteString(namespace)
			b.WriteRune('/')
			pos += n + 1
			b.WriteString(name)
			return ServiceName{
				str:           b.String(),
				clusterEndPos: uint16(cendPos),
				namePos:       uint16(pos),
			}
		},
	)
}

func (n ServiceName) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.str)
}

func (n *ServiceName) UnmarshalJSON(bs []byte) error {
	return n.unmarshalString(strings.Trim(string(bs), `"`))
}

func (n *ServiceName) unmarshalString(s string) error {
	s = strings.TrimSpace(s[:min(len(s), 65535)])
	orig := s
	n.str = s
	pos := 0
	popSlash := func() int {
		if len(s) > 0 {
			idx := strings.Index(s, "/")
			if idx >= 0 {
				s = s[idx+1:]
				pos += idx + 1
				return pos
			}
		}
		return -1
	}
	i1, i2 := popSlash(), popSlash()
	switch {
	case i1 < 0:
		n.str = ""
		return fmt.Errorf("invalid service name: no namespace in %q", orig)
	case i2 < 0:
		n.namePos = uint16(i1)
	default:
		n.clusterEndPos = uint16(i1)
		n.namePos = uint16(i2)
	}
	// Deduplicate
	*n = serviceNameCache.Get(*n)
	return nil
}

func (n ServiceName) MarshalYAML() (any, error) {
	return n.String(), nil
}

func (n *ServiceName) UnmarshalYAML(value *yaml.Node) error {
	return n.unmarshalString(value.Value)
}

func (n *ServiceName) Equal(other ServiceName) bool {
	return n.clusterEndPos == other.clusterEndPos &&
		n.namePos == other.namePos &&
		n.str == other.str
}

func (n ServiceName) Compare(other ServiceName) int {
	switch {
	case n.Namespace() < other.Namespace():
		return -1
	case n.Namespace() > other.Namespace():
		return 1
	case n.Name() < other.Name():
		return -1
	case n.Name() > other.Name():
		return 1
	case n.Cluster() < other.Cluster():
		return -1
	case n.Cluster() > other.Cluster():
		return 1
	default:
		return 0
	}
}

func (n ServiceName) String() string {
	return n.str
}

func (n ServiceName) AppendSuffix(suffix string) ServiceName {
	n.str += suffix
	return n
}

// BackendID is the backend's ID.
type BackendID uint32

// BackendState is the state of a backend for load-balancing service traffic.
type BackendState uint8

func (state BackendState) String() (string, error) {
	switch state {
	case BackendStateActive:
		return models.BackendAddressStateActive, nil
	case BackendStateTerminating:
		return models.BackendAddressStateTerminating, nil
	case BackendStateQuarantined:
		return models.BackendAddressStateQuarantined, nil
	case BackendStateMaintenance:
		return models.BackendAddressStateMaintenance, nil
	default:
		return "", fmt.Errorf("invalid backend state %d", state)
	}
}

func NewL4Type(name string) (L4Type, error) {
	switch strings.ToLower(name) {
	case "none":
		return NONE, nil
	case "any":
		return ANY, nil
	case "tcp":
		return TCP, nil
	case "udp":
		return UDP, nil
	case "sctp":
		return SCTP, nil
	default:
		return "", fmt.Errorf("unknown L4 protocol")
	}
}

func NewL4TypeFromNumber(proto uint8) L4Type {
	switch proto {
	case 6:
		return TCP
	case 17:
		return UDP
	case 132:
		return SCTP
	default:
		return ANY
	}
}

// L4Addr is an abstraction for the backend port with a L4Type, usually tcp or udp, and
// the Port number.
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type L4Addr struct {
	Protocol L4Type
	Port     uint16
}

// DeepEqual returns true if both the receiver and 'o' are deeply equal.
func (l *L4Addr) DeepEqual(o *L4Addr) bool {
	if l == nil {
		return o == nil
	}
	return l.deepEqual(o)
}

// NewL4Addr creates a new L4Addr.
func NewL4Addr(protocol L4Type, number uint16) L4Addr {
	return L4Addr{Protocol: protocol, Port: number}
}

// Equals returns true if both L4Addr are considered equal.
func (l L4Addr) Equals(o L4Addr) bool {
	return l.Port == o.Port && l.Protocol == o.Protocol
}

// String returns a string representation of an L4Addr
func (l L4Addr) String() string {
	return fmt.Sprintf("%d/%s", l.Port, l.Protocol)
}

// L3n4Addr is used to store, as an unique L3+L4 address in the KVStore. It also
// includes the lookup scope for frontend addresses which is used in service
// handling for externalTrafficPolicy=Local and internalTrafficPolicy=Local,
// that is, Scope{External,Internal}.
//
// +deepequal-gen=true
// +deepequal-gen:private-method=true
// +k8s:deepcopy-gen=true
type L3n4Addr struct {
	AddrCluster cmtypes.AddrCluster
	L4Addr
	Scope uint8
}

// DeepEqual returns true if both the receiver and 'o' are deeply equal.
func (l *L3n4Addr) DeepEqual(o *L3n4Addr) bool {
	if l == nil {
		return o == nil
	}
	return l.AddrCluster.Equal(o.AddrCluster) && l.deepEqual(o)
}

// NewL3n4Addr creates a new L3n4Addr.
func NewL3n4Addr(protocol L4Type, addrCluster cmtypes.AddrCluster, portNumber uint16, scope uint8) L3n4Addr {
	lbport := NewL4Addr(protocol, portNumber)
	return L3n4Addr{AddrCluster: addrCluster, L4Addr: lbport, Scope: scope}
}

func NewL3n4AddrFromModel(base *models.FrontendAddress) (*L3n4Addr, error) {
	var scope uint8

	if base == nil {
		return nil, nil
	}

	if base.IP == "" {
		return nil, fmt.Errorf("missing IP address")
	}

	proto := NONE
	if base.Protocol != "" {
		p, err := NewL4Type(base.Protocol)
		if err != nil {
			return nil, err
		}
		proto = p
	}

	l4addr := NewL4Addr(proto, base.Port)
	addrCluster, err := cmtypes.ParseAddrCluster(base.IP)
	if err != nil {
		return nil, err
	}

	if base.Scope == models.FrontendAddressScopeExternal {
		scope = ScopeExternal
	} else if base.Scope == models.FrontendAddressScopeInternal {
		scope = ScopeInternal
	} else {
		return nil, fmt.Errorf("invalid scope \"%s\"", base.Scope)
	}

	return &L3n4Addr{AddrCluster: addrCluster, L4Addr: l4addr, Scope: scope}, nil
}

// L3n4AddrFromString constructs a StateDB key by parsing the input in the form of
// L3n4Addr.String(), e.g. <addr>:<port>/protocol. The input can be partial to construct
// keys for prefix searches, e.g. "1.2.3.4".
// This must be kept in sync with Bytes().
func L3n4AddrFromString(key string) (index.Key, error) {
	keyErr := errors.New("bad key, expected \"<addr>:<port>/<proto>(/i)\", e.g. \"1.2.3.4:80/TCP\" or classful prefix \"10.0.0.0/8\"")
	var out []byte

	if len(key) == 0 {
		return index.Key{}, keyErr
	}

	// Parse address
	var addr string
	if strings.HasPrefix(key, "[") {
		addr, key, _ = strings.Cut(key[1:], "]")
		switch {
		case strings.HasPrefix(key, ":"):
			key = key[1:]
		case len(key) > 0:
			return index.Key{}, keyErr
		}
	} else {
		addr, key, _ = strings.Cut(key, ":")
	}

	addrCluster, err := cmtypes.ParseAddrCluster(addr)
	if err != nil {
		// See if the address is a prefix and try to parse it as such.
		// We only support classful searches, e.g. /8, /16, /24, /32 since
		// indexing is byte-wise.
		if prefix, err := netip.ParsePrefix(addr); err == nil {
			bits := prefix.Bits()
			if bits%8 != 0 {
				return index.Key{}, fmt.Errorf("%w: only classful prefixes supported (/8,/16,/24,/32)", keyErr)
			}
			bytes := prefix.Addr().As16()
			if prefix.Addr().Is6() {
				return index.Key(bytes[:bits/8]), nil
			} else {
				// The address is in the 16-byte format, cut from the last 4 bytes.
				return index.Key(bytes[:12+bits/8]), nil
			}
		}
		return index.Key{}, fmt.Errorf("%w: %w", keyErr, err)
	}
	addr20 := addrCluster.As20()
	out = append(out, addr20[:]...)

	// Parse port
	if len(key) > 0 {
		var s string
		s, key, _ = strings.Cut(key, "/")
		port, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return index.Key{}, fmt.Errorf("%w: %w", keyErr, err)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(port))
	}

	// Parse protocol
	hadProto := false
	if len(key) > 0 {
		var proto string
		proto, key, _ = strings.Cut(key, "/")
		protoByte := L4TypeAsByte(strings.ToUpper(proto))
		if protoByte == '?' {
			return index.Key{}, fmt.Errorf("%w: bad protocol, expected TCP/UDP/SCTP", keyErr)
		}
		out = append(out, protoByte)
		hadProto = true
	}

	// Parse scope.
	switch {
	case key == "i":
		out = append(out, ScopeInternal)
	case hadProto:
		// Since external scope is implicit we add it here if the protocol was
		// also provided. This way we can construct partial keys for prefix
		// searching and we can construct complete key for 'get'.
		out = append(out, ScopeExternal)
	}
	return index.Key(out), nil
}

func (l *L3n4Addr) ParseFromString(s string) error {
	formatError := fmt.Errorf(
		"bad address %q, expected \"<addr>:<port>/<proto>(/i)\", e.g. \"1.2.3.4:80/TCP\"",
		s,
	)

	// Parse address
	var addr string
	if strings.HasPrefix(s, "[") {
		addr, s, _ = strings.Cut(s[1:], "]")
		switch {
		case strings.HasPrefix(s, ":"):
			s = s[1:]
		case len(s) > 0:
			return formatError
		}
	} else {
		addr, s, _ = strings.Cut(s, ":")
	}

	var err error
	l.AddrCluster, err = cmtypes.ParseAddrCluster(addr)
	if err != nil {
		return formatError
	}

	// Parse port
	if len(s) < 1 {
		return formatError
	}

	var portS string
	portS, s, _ = strings.Cut(s, "/")
	port, err := strconv.ParseUint(portS, 10, 16)
	if err != nil {
		return formatError
	}
	l.L4Addr.Port = uint16(port)

	// Parse protocol
	l.L4Addr.Protocol = TCP
	if len(s) > 0 {
		var proto string
		proto, s, _ = strings.Cut(s, "/")
		l.L4Addr.Protocol = L4Type(strings.ToUpper(proto))
		if !slices.Contains(AllProtocols, l.L4Addr.Protocol) {
			return formatError
		}
	}

	// Parse scope.
	l.Scope = ScopeExternal
	if s == "i" {
		l.Scope = ScopeInternal
	}
	return nil
}

func (a *L3n4Addr) GetModel() *models.FrontendAddress {
	if a == nil {
		return nil
	}

	scope := models.FrontendAddressScopeExternal
	if a.Scope == ScopeInternal {
		scope = models.FrontendAddressScopeInternal
	}
	return &models.FrontendAddress{
		IP:       a.AddrCluster.String(),
		Protocol: a.Protocol,
		Port:     a.Port,
		Scope:    scope,
	}
}

// String returns the L3n4Addr in the "IPv4:Port/Protocol[/Scope]" format for IPv4 and
// "[IPv6]:Port/Protocol[/Scope]" format for IPv6.
func (a *L3n4Addr) String() string {
	return a.StringWithProtocol()
}

// StringWithProtocol returns the L3n4Addr in the "IPv4:Port/Protocol[/Scope]"
// format for IPv4 and "[IPv6]:Port/Protocol[/Scope]" format for IPv6.
func (a *L3n4Addr) StringWithProtocol() string {
	var scope string
	if a.Scope == ScopeInternal {
		scope = "/i"
	}
	if a.IsIPv6() {
		return "[" + a.AddrCluster.String() + "]:" + strconv.FormatUint(uint64(a.Port), 10) + "/" + a.Protocol + scope
	}
	return a.AddrCluster.String() + ":" + strconv.FormatUint(uint64(a.Port), 10) + "/" + a.Protocol + scope
}

// StringID returns the L3n4Addr as string to be used for unique identification
func (a *L3n4Addr) StringID() string {
	return a.String()
}

// IsIPv6 returns true if the IP address in the given L3n4Addr is IPv6 or not.
func (a *L3n4Addr) IsIPv6() bool {
	return a.AddrCluster.Is6()
}

func (l *L3n4Addr) AddrString() string {
	str := l.AddrCluster.Addr().String() + ":" + strconv.FormatUint(uint64(l.Port), 10)

	return str
}

type l3n4AddrCacheEntry struct {
	addr  L3n4Addr
	bytes []byte
}

var l3n4AddrCache = cache.New(
	func(e l3n4AddrCacheEntry) uint64 {
		return e.addr.l3n4AddrCacheHash()
	},
	nil,
	func(a, b l3n4AddrCacheEntry) bool {
		return bytes.Equal(a.bytes, b.bytes)
	},
)

func (l L3n4Addr) l3n4AddrCacheHash() uint64 {
	var d xxhash.Digest
	buf := l.AddrCluster.Addr().As16()
	d.Write(buf[:])
	binary.BigEndian.PutUint16(buf[:], l.Port)
	d.Write(buf[:2])
	return d.Sum64()
}

// Bytes returns the address as a byte slice for indexing purposes.
// Similar to Hash() but includes the L4 protocol.
func (l L3n4Addr) Bytes() []byte {
	return cache.GetOrPutWith(
		l3n4AddrCache,
		l.l3n4AddrCacheHash(),
		func(e l3n4AddrCacheEntry) bool {
			return e.addr.DeepEqual(&l)
		},
		func() l3n4AddrCacheEntry {
			const keySize = cmtypes.AddrClusterLen +
				2 /* Port */ +
				1 /* Protocol */ +
				1 /* Scope */

			key := make([]byte, 0, keySize)
			addr20 := l.AddrCluster.As20()
			key = append(key, addr20[:]...)
			key = binary.BigEndian.AppendUint16(key, l.Port)
			key = append(key, L4TypeAsByte(l.Protocol))
			key = append(key, l.Scope)
			return l3n4AddrCacheEntry{
				addr:  l,
				bytes: key,
			}
		}).bytes
}

func (l L3n4Addr) MarshalYAML() (any, error) {
	return l.StringWithProtocol(), nil

}
func (l *L3n4Addr) UnmarshalYAML(value *yaml.Node) error {
	return l.ParseFromString(value.Value)
}

func NewL3n4AddrFromBackendModel(base *models.BackendAddress) (*L3n4Addr, error) {
	if base.IP == nil {
		return nil, fmt.Errorf("missing IP address")
	}

	l4addr := NewL4Addr(base.Protocol, base.Port)
	addrCluster, err := cmtypes.ParseAddrCluster(*base.IP)
	if err != nil {
		return nil, err
	}
	return &L3n4Addr{AddrCluster: addrCluster, L4Addr: l4addr}, nil
}

func init() {
	// Register the types for use with part.Map and part.Set.
	part.RegisterKeyType(
		func(name ServiceName) []byte { return []byte(name.Key()) })
	part.RegisterKeyType(L3n4Addr.Bytes)
}
