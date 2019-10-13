// Copyright 2019 Authors of Cilium
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

package endpoint

import (
	"sort"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

func getEndpointStatusControllers(status *models.EndpointStatus) (controllers cilium_v2.ControllerList) {
	for _, c := range status.Controllers {
		if c.Status == nil {
			continue
		}

		if c.Status.ConsecutiveFailureCount > 0 {
			s := cilium_v2.ControllerStatus{
				Configuration: c.Configuration,
				Name:          c.Name,
				UUID:          string(c.UUID),
				Status: cilium_v2.ControllerStatusStatus{
					ConsecutiveFailureCount: c.Status.ConsecutiveFailureCount,
					FailureCount:            c.Status.FailureCount,
					LastFailureMsg:          c.Status.LastFailureMsg,
					LastFailureTimestamp:    c.Status.LastFailureTimestamp.String(),
					LastSuccessTimestamp:    c.Status.LastSuccessTimestamp.String(),
					SuccessCount:            c.Status.SuccessCount,
				},
			}
			if controllers == nil {
				controllers = cilium_v2.ControllerList{s}
			} else {
				controllers = append(controllers, s)
			}
		}
	}

	if controllers != nil {
		controllers.Sort()
	}

	return
}

func (e *Endpoint) getEndpointStatusLog() (log []*models.EndpointStatusChange) {
	added := 0

	if s := e.status; s != nil {
		s.indexMU.RLock()
		defer s.indexMU.RUnlock()

		for i := s.lastIndex(); ; i-- {
			if i < 0 {
				i = maxLogs - 1
			}
			if i < len(s.Log) && s.Log[i] != nil {
				l := &models.EndpointStatusChange{
					Timestamp: s.Log[i].Timestamp.Format(time.RFC3339),
					Code:      s.Log[i].Status.Code.String(),
					Message:   s.Log[i].Status.Msg,
					State:     models.EndpointState(s.Log[i].Status.State),
				}

				if strings.ToLower(l.Code) != models.EndpointStatusChangeCodeOk {
					if log == nil {
						log = []*models.EndpointStatusChange{l}
					} else {
						log = append(log, l)
					}

					// Limit the number of endpoint log
					// entries to keep the size of the
					// EndpointStatus low.
					added++
					if added >= cilium_v2.EndpointStatusLogEntries {
						break
					}
				}
			}
			if i == s.Index {
				break
			}
		}
	}
	return
}

func getEndpointIdentity(status *models.EndpointStatus) (identity *cilium_v2.EndpointIdentity) {
	if status.Identity != nil {
		identity = &cilium_v2.EndpointIdentity{
			ID: status.Identity.ID,
		}

		identity.Labels = make([]string, len(status.Identity.Labels))
		copy(identity.Labels, status.Identity.Labels)
		sort.Strings(identity.Labels)
	}
	return
}

func getEndpointNetworking(status *models.EndpointStatus) (networking *cilium_v2.EndpointNetworking) {
	if status.Networking != nil {
		networking = &cilium_v2.EndpointNetworking{
			Addressing: make(cilium_v2.AddressPairList, len(status.Networking.Addressing)),
		}

		if option.Config.EnableIPv4 {
			networking.NodeIP = node.GetExternalIPv4().String()
		} else {
			networking.NodeIP = node.GetIPv6().String()
		}

		i := 0
		for _, pair := range status.Networking.Addressing {
			networking.Addressing[i] = &cilium_v2.AddressPair{
				IPV4: pair.IPV4,
				IPV6: pair.IPV6,
			}
			i++
		}

		networking.Addressing.Sort()
	}
	return
}

// updateLabels inserts the labels correnspoding to the specified identity into
// the AllowedIdentityTuple.
func updateLabels(allocator cache.IdentityAllocator, allowedIdentityTuple *cilium_v2.AllowedIdentityTuple, secID identity.NumericIdentity) {
	// IdentityUnknown denotes that this is an L4-only BPF
	// allow, so it applies to all identities. In this case
	// we should skip resolving the labels, because the
	// value 0 does not denote an allow for the "unknown"
	// identity, but instead an allow of all identities for
	// that port.
	if secID != identity.IdentityUnknown {
		identity := allocator.LookupIdentityByID(secID)
		if identity != nil {
			var l labels.Labels
			if identity.CIDRLabel != nil {
				l = identity.CIDRLabel
			} else {
				l = identity.Labels
			}

			allowedIdentityTuple.IdentityLabels = l.StringMap()
		}
	}
}

// populateResponseWithPolicyKey inserts an AllowedIdentityTuple element into 'policy'
// which corresponds to the specified 'desiredPolicy'.
func populateResponseWithPolicyKey(allocator cache.IdentityAllocator, policy *cilium_v2.EndpointPolicy, policyKey *policy.Key) {
	allowedIdentityTuple := cilium_v2.AllowedIdentityTuple{
		DestPort: policyKey.DestPort,
		Protocol: policyKey.Nexthdr,
		Identity: uint64(policyKey.Identity),
	}

	secID := identity.NumericIdentity(policyKey.Identity)
	updateLabels(allocator, &allowedIdentityTuple, secID)

	switch {
	case policyKey.IsIngress():
		if policy.Ingress.Allowed == nil {
			policy.Ingress.Allowed = cilium_v2.AllowedIdentityList{allowedIdentityTuple}
		} else {
			policy.Ingress.Allowed = append(policy.Ingress.Allowed, allowedIdentityTuple)
		}
	case policyKey.IsEgress():
		if policy.Egress.Allowed == nil {
			policy.Egress.Allowed = cilium_v2.AllowedIdentityList{allowedIdentityTuple}
		} else {
			policy.Egress.Allowed = append(policy.Egress.Allowed, allowedIdentityTuple)
		}
	}
}

// desiredPolicyAllowsIdentity returns whether the specified policy allows
// ingress and egress traffic for the specified numeric security identity.
// If the 'secID' is zero, it will check if all traffic is allowed.
//
// Returing true for either return value indicates all traffic is allowed.
func desiredPolicyAllowsIdentity(desired *policy.EndpointPolicy, identity identity.NumericIdentity) (ingress, egress bool) {
	key := policy.Key{
		Identity: uint32(identity),
	}

	key.TrafficDirection = trafficdirection.Ingress.Uint8()
	if _, ok := desired.PolicyMapState[key]; ok || !desired.IngressPolicyEnabled {
		ingress = true
	}
	key.TrafficDirection = trafficdirection.Egress.Uint8()
	if _, ok := desired.PolicyMapState[key]; ok || !desired.EgressPolicyEnabled {
		egress = true
	}

	return ingress, egress
}

// getEndpointPolicy returns an API representation of the policy that the
// received Endpoint intends to apply.
func (e *Endpoint) getEndpointPolicy() (policy *cilium_v2.EndpointPolicy) {
	if e.desiredPolicy != nil {
		policy = &cilium_v2.EndpointPolicy{
			Ingress: &cilium_v2.EndpointPolicyDirection{
				Enforcing: e.desiredPolicy.IngressPolicyEnabled,
			},
			Egress: &cilium_v2.EndpointPolicyDirection{
				Enforcing: e.desiredPolicy.EgressPolicyEnabled,
			},
		}

		// Handle allow-all cases
		allowsAllIngress, allowsAllEgress := desiredPolicyAllowsIdentity(e.desiredPolicy, identity.IdentityUnknown)
		if allowsAllIngress {
			policy.Ingress.Allowed = cilium_v2.AllowedIdentityList{{}}
		}
		if allowsAllEgress {
			policy.Egress.Allowed = cilium_v2.AllowedIdentityList{{}}
		}

		// If either ingress or egress policy is enabled, go through
		// the desired policy to populate the values.
		if !allowsAllIngress || !allowsAllEgress {
			allowsWorldIngress, allowsWorldEgress := desiredPolicyAllowsIdentity(e.desiredPolicy, identity.ReservedIdentityWorld)

			for policyKey := range e.desiredPolicy.PolicyMapState {
				// Skip listing identities if enforcement is disabled in direction,
				// or if the identity corresponds to a CIDR identity and the world is allowed.
				id := identity.NumericIdentity(policyKey.Identity)
				switch {
				case policyKey.IsIngress():
					if allowsAllIngress || (id.HasLocalScope() && allowsWorldIngress) {
						continue
					}
				case policyKey.IsEgress():
					if allowsAllEgress || (id.HasLocalScope() && allowsWorldEgress) {
						continue
					}
				}

				populateResponseWithPolicyKey(e.allocator, policy, &policyKey)
			}
		}

		if policy.Ingress.Allowed != nil {
			policy.Ingress.Allowed.Sort()
		}
		if policy.Egress.Allowed != nil {
			policy.Egress.Allowed.Sort()
		}
	}

	return
}

// GetCiliumEndpointStatus creates a cilium_v2.EndpointStatus of an endpoint.
// See cilium_v2.EndpointStatus for a detailed explanation of each field.
func (e *Endpoint) GetCiliumEndpointStatus() *cilium_v2.EndpointStatus {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	model := e.GetModelRLocked()
	modelStatus := model.Status

	controllers := getEndpointStatusControllers(modelStatus)
	identity := getEndpointIdentity(modelStatus)
	log := e.getEndpointStatusLog()
	networking := getEndpointNetworking(modelStatus)

	return &cilium_v2.EndpointStatus{
		ID:                  int64(e.ID),
		ExternalIdentifiers: modelStatus.ExternalIdentifiers,
		Controllers:         controllers,
		Identity:            identity,
		Log:                 log,
		Networking:          networking,
		Health:              modelStatus.Health,
		State:               string(modelStatus.State),
		Policy:              e.getEndpointPolicy(),
		Encryption:          cilium_v2.EncryptionSpec{Key: int(node.GetIPsecKeyIdentity())},

		// Scheduled for deprecation in 1.5
		//
		// Status is deprecated but we have some users depending on
		// these fields so they continue to be populated until version
		// 1.5
		Status: &cilium_v2.DeprecatedEndpointStatus{
			Controllers: controllers,
			Identity:    identity,
			Log:         log,
			Networking:  networking,
		},
	}
}
