// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicies

import (
	"fmt"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy/api"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

type podID = resource.Key

// podMetadata stores relevant metadata associated with a pod that's updated during pod
// add/update events
type podMetadata struct {
	labels map[string]string
	// id the pod's name and namespace
	id podID
	// ips are pod's unique IPs
	ips []string
	// namedPorts stores pod port and protocol indexed by the port name
	namedPorts serviceStore.PortConfiguration
}

type lrpConfigType = int

const (
	lrpConfigTypeNone = iota
	// LRP config is specified using IP/port tuple.
	lrpConfigTypeAddr
	// LRP config is specified using Kubernetes service name and namespace.
	lrpConfigTypeSvc
)

// LRPConfig is the internal representation of Cilium Local Redirect Policy.
type LRPConfig struct {
	key              resource.Key         // key of the CiliumLocalRedirectPolicy
	lrpType          lrpConfigType        // address or service matcher
	serviceID        *resource.Key        // service name and namespace if service redirect
	backendSelector  api.EndpointSelector // pod selector as specified by policy
	backendPorts     []bePortInfo         // the optional backend ports
	frontendMappings []*feMapping         // the frontend ports we should match
	podBackends      map[resource.Key][]lb.Backend
	podUntrack       func()
}

type frontend = loadbalancer.L3n4Addr

// backend encapsulates loadbalancer.L3n4Addr for a pod along with podID (pod
// name and namespace). There can be multiple backend pods for an LRP frontend,
// in such cases, the podID will be used to keep track of updates related to
// a pod.
type backend struct {
	loadbalancer.L3n4Addr
	podID podID
}

func (be *backend) GetModel() *models.LRPBackend {
	ip := be.AddrCluster.String()
	return &models.LRPBackend{
		PodID: be.podID.String(),
		BackendAddress: &models.BackendAddress{
			IP:   &ip,
			Port: be.Port,
		},
	}
}

type portName = string

// feMapping stores frontend address and a list of associated backend addresses.
type feMapping struct {
	feAddr     lb.L3n4Addr
	fePortName portName
}

type bePortInfo struct {
	// l4Addr is the port and protocol
	l4Addr lb.L4Addr
	// name is the port name
	name string
}

// PolicyID includes policy name and namespace
type policyID = resource.Key

// Parse parses the specified cilium local redirect policy spec, and returns
// a sanitized LRPConfig.
func Parse(clrp *v2.CiliumLocalRedirectPolicy, sanitize bool) (*LRPConfig, error) {
	key := resource.NewKey(clrp)

	if sanitize {
		return getSanitizedLRPConfig(key, clrp.UID, clrp.Spec)
	} else {
		return &LRPConfig{}, nil
	}
}

func getSanitizedLRPConfig(key resource.Key, uid types.UID, spec v2.CiliumLocalRedirectPolicySpec) (*LRPConfig, error) {

	var (
		addrMatcher    = spec.RedirectFrontend.AddressMatcher
		svcMatcher     = spec.RedirectFrontend.ServiceMatcher
		redirectTo     = spec.RedirectBackend
		checkNamedPort = false
		lrpType        lrpConfigType
		k8sSvc         *resource.Key
		fe             *frontend
		feMappings     []*feMapping
		bePorts        []bePortInfo
		bePortsMap     = make(map[portName]*bePortInfo)
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
			return nil, fmt.Errorf("invalid address matcher IP %v: %s", addrMatcher.IP, err)
		}
		if len(addrMatcher.ToPorts) > 1 {
			// If there are multiple ports, then the ports must be named.
			checkNamedPort = true
		} else if len(addrMatcher.ToPorts) == 1 {
		}
		feMappings = make([]*feMapping, len(addrMatcher.ToPorts))
		for i, portInfo := range addrMatcher.ToPorts {
			p, pName, proto, err := portInfo.SanitizePortInfo(checkNamedPort)
			if err != nil {
				return nil, fmt.Errorf("invalid address matcher port %v", err)
			}
			// Set the scope to ScopeExternal as the externalTrafficPolicy is set to Cluster.
			fe = loadbalancer.NewL3n4Addr(proto, addrCluster, p, loadbalancer.ScopeExternal)
			feM := &feMapping{
				feAddr:     *fe,
				fePortName: pName,
			}
			feMappings[i] = feM
		}
		lrpType = lrpConfigTypeAddr
	case svcMatcher != nil:
		// LRP specifies service config for traffic that needs to be redirected.
		k8sSvc = &resource.Key{
			Name:      svcMatcher.Name,
			Namespace: svcMatcher.Namespace,
		}
		if k8sSvc.Name == "" {
			return nil, fmt.Errorf("kubernetes service name can" +
				"not be empty")
		}
		if key.Namespace != "" && k8sSvc.Namespace != key.Namespace {
			return nil, fmt.Errorf("kubernetes service namespace" +
				"does not match with the CiliumLocalRedirectPolicy namespace")
		}
		feMappings = make([]*feMapping, len(svcMatcher.ToPorts))
		for i, portInfo := range svcMatcher.ToPorts {
			p, pName, proto, err := portInfo.SanitizePortInfo(checkNamedPort)
			if err != nil {
				return nil, fmt.Errorf("invalid service matcher port %v", err)
			}
			// Set the scope to ScopeExternal as the externalTrafficPolicy is set to Cluster.
			// frontend ip will later be populated with the clusterIP of the service.
			fe = loadbalancer.NewL3n4Addr(proto, cmtypes.AddrCluster{}, p, loadbalancer.ScopeExternal)
			feM := &feMapping{
				feAddr:     *fe,
				fePortName: pName,
			}
			feMappings[i] = feM
		}
		lrpType = lrpConfigTypeSvc
	default:
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
			return nil, fmt.Errorf("invalid backend port %v", err)
		}
		beP := bePortInfo{
			l4Addr: lb.L4Addr{
				Protocol: proto,
				Port:     p,
			},
			name: pName,
		}
		bePorts[i] = beP
		if len(pName) > 0 {
			// Port name is present.
			bePortsMap[pName] = &bePorts[i]

		}
	}
	// When a single port is specified in the LRP frontend, the protocol for frontend and
	// backend must match.
	if len(feMappings) == 1 {
		if bePorts[0].l4Addr.Protocol != feMappings[0].feAddr.Protocol {
			return nil, fmt.Errorf("backend protocol must match with " +
				"frontend protocol")
		}
	}

	// Get an EndpointSelector from the passed policy labelSelector for optimized matching.
	selector := api.NewESFromK8sLabelSelector("", &redirectTo.LocalEndpointSelector)

	return &LRPConfig{
		serviceID:        k8sSvc,
		frontendMappings: feMappings,
		backendSelector:  selector,
		backendPorts:     bePorts,
		lrpType:          lrpType,
	}, nil
}

// policyConfigSelectsPod determines if the given pod is selected by the policy
// config based on matching labels of config and pod.
func (config *LRPConfig) policyConfigSelectsPod(pod *slim_corev1.Pod) bool {
	return config.backendSelector.Matches(labels.Set(pod.Labels))
}

// checkNamespace returns true if config namespace matches with the given namespace.
// The namespace check isn't applicable for clusterwide LRPs.
func (config *LRPConfig) checkNamespace(namespace string) bool {
	if config.key.Namespace != "" {
		return namespace == config.key.Namespace
	}
	return true
}

func (config *LRPConfig) GetModel() *models.LRPSpec {
	if config == nil {
		return nil
	}

	var feType, lrpType string
	feType = "TODO"
	switch config.lrpType {
	case lrpConfigTypeNone:
		lrpType = "none"
	case lrpConfigTypeAddr:
		lrpType = "addr"
	case lrpConfigTypeSvc:
		lrpType = "svc"
	}

	panic("TODO")
	/*
		feMappingModelArray := make([]*models.FrontendMapping, 0, len(config.frontendMappings))
		for _, feM := range config.frontendMappings {
			feMappingModelArray = append(feMappingModelArray, feM.GetModel())
		}*/

	var svcID string
	if config.serviceID != nil {
		svcID = config.serviceID.String()
	}

	return &models.LRPSpec{
		Name:         config.key.Name,
		Namespace:    config.key.Namespace,
		FrontendType: feType,
		LrpType:      lrpType,
		ServiceID:    svcID,
	}
}
