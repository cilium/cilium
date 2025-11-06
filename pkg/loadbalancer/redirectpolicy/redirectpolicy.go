// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"fmt"
	"log/slog"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

// localRedirectServiceSuffix is the suffix to append to the local redirect policy
// name to construct the pseudo-service name to which the matched pods are associated
// as backends. ':' is used as separator as that is not an allowed character in k8s.
const localRedirectServiceSuffix = ":local-redirect"

func lrpServiceName(lrpID lb.ServiceName) lb.ServiceName {
	return lrpID.AppendSuffix(localRedirectServiceSuffix)
}

type lrpConfigType = int

const (
	lrpConfigTypeNone = iota
	// LRP config is specified using IP/port tuple.
	lrpConfigTypeAddr
	// LRP config is specified using Kubernetes service name and namespace.
	lrpConfigTypeSvc
)

func lrpConfigTypeString(t lrpConfigType) string {
	switch t {
	case lrpConfigTypeNone:
		return "none"
	case lrpConfigTypeAddr:
		return "address"
	case lrpConfigTypeSvc:
		return "service"
	default:
		return "unknown"
	}
}

type frontendConfigType = int

const (
	frontendTypeUnknown = iota
	// Get frontends for service with clusterIP and all service ports.
	svcFrontendAll
	// Get frontends for service with clusterIP and parsed config named ports.
	svcFrontendNamedPorts
	// Get a frontend for service with clusterIP and parsed config port.
	svcFrontendSinglePort
	// Get a frontend with parsed config frontend IP and port.
	addrFrontendSinglePort
	// Get frontends with parsed config frontend IPs and named ports.
	addrFrontendNamedPorts
)

func frontendConfigTypeString(t frontendConfigType) string {
	switch t {
	case svcFrontendAll:
		return "all"
	case svcFrontendNamedPorts:
		return "named-ports"
	case svcFrontendSinglePort:
		return "svc-single-port"
	case addrFrontendSinglePort:
		return "addr-single-port"
	case addrFrontendNamedPorts:
		return "addr-named-ports"
	default:
		return "unknown"
	}
}

// LocalRedirectPolicy is the internal representation of Cilium Local Redirect Policy.
type LocalRedirectPolicy struct {
	// ID is the parsed config name and namespace
	ID lb.ServiceName
	// UID is the unique identifier assigned by Kubernetes
	UID types.UID
	// LRPType is the type of either address matcher or service matcher policy
	LRPType lrpConfigType
	// FrontendType is the type for the parsed config frontend.
	FrontendType frontendConfigType
	// FrontendMappings is a slice of policy config frontend mappings that include
	// frontend address, frontend port name, and a slice of its associated backends
	FrontendMappings []feMapping
	// ServiceID is the parsed service name and namespace
	ServiceID lb.ServiceName
	// BackendSelector is an endpoint selector generated from the parsed policy selector
	BackendSelector *policytypes.LabelSelector
	// BackendPorts is a slice of backend port and protocol along with the port name
	BackendPorts []bePortInfo
	// BackendPortsByPortName is a map indexed by port name with the value as
	// a pointer to bePortInfo for easy lookup into backendPorts
	BackendPortsByPortName map[lb.FEPortName]bePortInfo
	// SkipRedirectFromBackend is the flag that enables/disables redirection
	// for traffic matching the policy frontend(s) from the backends selected by the policy
	SkipRedirectFromBackend bool
}

func (lrp *LocalRedirectPolicy) TableHeader() []string {
	return []string{
		"Name",
		"Type",
		"Service",
		"FrontendType",
		"Frontends",
		"BackendSelector",
	}
}

func (lrp *LocalRedirectPolicy) TableRow() []string {
	mappings := make([]string, 0, len(lrp.FrontendMappings))
	for _, feM := range lrp.FrontendMappings {
		mappings = append(mappings, feM.feAddr.StringWithProtocol())
	}
	return []string{
		lrp.ID.String(),
		lrpConfigTypeString(lrp.LRPType),
		lrp.ServiceID.String(),
		frontendConfigTypeString(lrp.FrontendType),
		strings.Join(mappings, ", "),
		lrp.BackendSelector.Key(),
	}
}

func (lrp *LocalRedirectPolicy) RedirectServiceName() lb.ServiceName {
	return lrpServiceName(lrp.ID)
}

// feMapping stores frontend address and a list of associated backend addresses.
type feMapping struct {
	feAddr lb.L3n4Addr
	fePort lb.FEPortName
}

func (m feMapping) String() string {
	return fmt.Sprintf("%s (%s)", m.feAddr.StringWithProtocol(), m.fePort)
}

type bePortInfo struct {
	// l4Addr is the port and protocol
	l4Addr lb.L4Addr
	// name is the port name
	name lb.FEPortName
}

func (p bePortInfo) String() string {
	return fmt.Sprintf("%s (%s)", &p.l4Addr, p.name)
}

// parse parses the specified cilium local redirect policy spec, and returns
// a sanitized LocalRedirectPolicy.
func parseLRP(cfg Config, log *slog.Logger, clrp *v2.CiliumLocalRedirectPolicy) (*LocalRedirectPolicy, error) {
	name := clrp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("CiliumLocalRedirectPolicy must have a name")
	}

	namespace := k8sUtils.ExtractNamespace(&clrp.ObjectMeta)
	if namespace == "" {
		return nil, fmt.Errorf("CiliumLocalRedirectPolicy must have a non-empty namespace")
	}

	return getSanitizedLocalRedirectPolicy(cfg, log, name, namespace, clrp.UID, clrp.Spec)
}

func getSanitizedLocalRedirectPolicy(cfg Config, log *slog.Logger, name, namespace string, uid types.UID, spec v2.CiliumLocalRedirectPolicySpec) (*LocalRedirectPolicy, error) {

	var (
		addrMatcher    = spec.RedirectFrontend.AddressMatcher
		svcMatcher     = spec.RedirectFrontend.ServiceMatcher
		redirectTo     = spec.RedirectBackend
		frontendType   = frontendTypeUnknown
		checkNamedPort = false
		lrpType        lrpConfigType
		k8sSvc         lb.ServiceName
		fe             lb.L3n4Addr
		feMappings     []feMapping
		bePorts        []bePortInfo
		bePortsMap     = make(map[lb.FEPortName]bePortInfo)
	)

	// Parse frontend config
	switch {
	case addrMatcher == nil && svcMatcher == nil:
		return nil, fmt.Errorf("both address and service" +
			" matchers can not be empty")
	case addrMatcher != nil && svcMatcher != nil:
		return nil, fmt.Errorf("both address and service" +
			" matchers can not be specified")
	case addrMatcher != nil:
		// LRP specifies IP/port tuple config for traffic that needs to be redirected.
		addrCluster, err := cmtypes.ParseAddrCluster(addrMatcher.IP)
		if err != nil {
			return nil, fmt.Errorf("invalid address matcher IP %v: %w", addrMatcher.IP, err)
		}

		if !cfg.addressAllowed(addrCluster.Addr()) {
			return nil, fmt.Errorf("address %q in AddressMatcher disallowed by --"+AddressMatcherCIDRsName, addrMatcher.IP)
		}

		if len(addrMatcher.ToPorts) > 1 {
			// If there are multiple ports, then the ports must be named.
			checkNamedPort = true
			frontendType = addrFrontendNamedPorts
		} else if len(addrMatcher.ToPorts) == 1 {
			frontendType = addrFrontendSinglePort
		}
		feMappings = make([]feMapping, len(addrMatcher.ToPorts))
		for i, portInfo := range addrMatcher.ToPorts {
			p, pName, proto, err := portInfo.SanitizePortInfo(checkNamedPort)
			if err != nil {
				return nil, fmt.Errorf("invalid address matcher port: %w", err)
			}
			// Set the scope to ScopeExternal as the externalTrafficPolicy is set to Cluster.
			fe = lb.NewL3n4Addr(proto, addrCluster, p, lb.ScopeExternal)
			feMappings[i] = feMapping{
				feAddr: fe,
				fePort: lb.FEPortName(pName),
			}
		}
		lrpType = lrpConfigTypeAddr
	case svcMatcher != nil:
		// LRP specifies service config for traffic that needs to be redirected.
		k8sSvc = lb.NewServiceName(svcMatcher.Namespace, svcMatcher.Name)
		if k8sSvc.Name() == "" {
			return nil, fmt.Errorf("kubernetes service name can" +
				"not be empty")
		}
		if namespace != "" && k8sSvc.Namespace() != namespace {
			return nil, fmt.Errorf("kubernetes service namespace" +
				"does not match with the CiliumLocalRedirectPolicy namespace")
		}
		switch len(svcMatcher.ToPorts) {
		case 0:
			frontendType = svcFrontendAll
		case 1:
			frontendType = svcFrontendSinglePort
		default:
			frontendType = svcFrontendNamedPorts
			checkNamedPort = true
		}
		feMappings = make([]feMapping, len(svcMatcher.ToPorts))
		for i, portInfo := range svcMatcher.ToPorts {
			p, pName, proto, err := portInfo.SanitizePortInfo(checkNamedPort)
			if err != nil {
				return nil, fmt.Errorf("invalid service matcher port: %w", err)
			}
			// Set the scope to ScopeExternal as the externalTrafficPolicy is set to Cluster.
			// frontend ip will later be populated with the clusterIP of the service.
			fe = lb.NewL3n4Addr(proto, cmtypes.AddrCluster{}, p, lb.ScopeExternal)
			feMappings[i] = feMapping{
				feAddr: fe,
				fePort: lb.FEPortName(pName),
			}
		}
		lrpType = lrpConfigTypeSvc
	default:
		return nil, fmt.Errorf("invalid local redirect policy %v", spec)
	}

	if lrpType == lrpConfigTypeNone || frontendType == frontendTypeUnknown {
		return nil, fmt.Errorf("invalid local redirect policy %v", spec)
	}

	// Parse backend config
	bePorts = make([]bePortInfo, len(redirectTo.ToPorts))
	if len(redirectTo.ToPorts) > 1 {
		// We check for backend named ports if either frontend/backend have
		// multiple ports.
		checkNamedPort = true
	}
	for i, portInfo := range redirectTo.ToPorts {
		p, pName, proto, err := portInfo.SanitizePortInfo(checkNamedPort)
		if err != nil {
			return nil, fmt.Errorf("invalid backend port: %w", err)
		}
		beP := bePortInfo{
			l4Addr: lb.L4Addr{
				Protocol: proto,
				Port:     p,
			},
			name: lb.FEPortName(pName),
		}
		bePorts[i] = beP
		if len(pName) > 0 {
			// Port name is present.
			bePortsMap[lb.FEPortName(pName)] = bePorts[i]

		}
	}
	// When a single port is specified in the LRP frontend, the protocol for frontend and
	// backend must match.
	if len(feMappings) == 1 {
		if bePorts[0].l4Addr.Protocol != feMappings[0].feAddr.Protocol() {
			return nil, fmt.Errorf("backend protocol must match with " +
				"frontend protocol")
		}
	}

	// Get an EndpointSelector from the passed policy labelSelector for optimized matching.
	sel := policytypes.NewLabelSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &redirectTo.LocalEndpointSelector))

	return &LocalRedirectPolicy{
		UID:                     uid,
		ServiceID:               k8sSvc,
		FrontendMappings:        feMappings,
		BackendSelector:         sel,
		BackendPorts:            bePorts,
		BackendPortsByPortName:  bePortsMap,
		LRPType:                 lrpType,
		FrontendType:            frontendType,
		SkipRedirectFromBackend: spec.SkipRedirectFromBackend,
		ID:                      lb.NewServiceName(namespace, name),
	}, nil
}
