// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package cep contains the CiliumEndpoint event handling logic from Kubernetes.
package cep

import (
	"net"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/u8proto"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "k8s-watcher-cep")

func (s *Subscriber) OnAddCiliumEndpoint(ep *types.CiliumEndpoint) error {
	return s.OnUpdateCiliumEndpoint(nil, ep)
}

func (s *Subscriber) OnUpdateCiliumEndpoint(oldCEP, newCEP *types.CiliumEndpoint) error {
	var namedPortsChanged bool
	defer func() {
		if namedPortsChanged {
			s.pt.TriggerPolicyUpdates(true, "Named ports added or updated")
		}
	}()

	var ipsAdded []string
	if oldCEP != nil && oldCEP.Networking != nil {
		// Delete the old IP addresses from the IP cache
		defer func() {
			for _, oldPair := range oldCEP.Networking.Addressing {
				v4Added, v6Added := false, false
				for _, ipAdded := range ipsAdded {
					if ipAdded == oldPair.IPV4 {
						v4Added = true
					}
					if ipAdded == oldPair.IPV6 {
						v6Added = true
					}
				}
				if !v4Added {
					portsChanged := s.ipc.Delete(oldPair.IPV4, source.CustomResource)
					if portsChanged {
						namedPortsChanged = true
					}
				}
				if !v6Added {
					portsChanged := s.ipc.Delete(oldPair.IPV6, source.CustomResource)
					if portsChanged {
						namedPortsChanged = true
					}
				}
			}
		}()
	}

	// default to the standard sey
	encryptionKey := node.GetIPsecKeyIdentity()

	id := identity.ReservedIdentityUnmanaged
	if newCEP.Identity != nil {
		id = identity.NumericIdentity(newCEP.Identity.ID)
	}

	if newCEP.Encryption != nil {
		encryptionKey = uint8(newCEP.Encryption.Key)
	}

	if newCEP.Networking == nil || newCEP.Networking.NodeIP == "" {
		// When upgrading from an older version, the nodeIP may
		// not be available yet in the CiliumEndpoint and we
		// have to wait for it to be propagated
		return nil
	}

	nodeIP := net.ParseIP(newCEP.Networking.NodeIP)
	if nodeIP == nil {
		log.WithField("nodeIP", newCEP.Networking.NodeIP).Warning("Unable to parse node IP while processing CiliumEndpoint update")
		return nil
	}

	k8sMeta := &ipcache.K8sMetadata{
		Namespace:  newCEP.Namespace,
		PodName:    newCEP.Name,
		NamedPorts: make(policy.NamedPortMap, len(newCEP.NamedPorts)),
	}
	for _, port := range newCEP.NamedPorts {
		p, err := u8proto.ParseProtocol(port.Protocol)
		if err != nil {
			continue
		}
		k8sMeta.NamedPorts[port.Name] = policy.PortProto{
			Port:  port.Port,
			Proto: uint8(p),
		}
	}

	for _, pair := range newCEP.Networking.Addressing {
		if pair.IPV4 != "" {
			ipsAdded = append(ipsAdded, pair.IPV4)
			portsChanged, _ := s.ipc.Upsert(pair.IPV4, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}

		if pair.IPV6 != "" {
			ipsAdded = append(ipsAdded, pair.IPV6)
			portsChanged, _ := s.ipc.Upsert(pair.IPV6, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}
	}

	return nil
}

func (s *Subscriber) OnDeleteCiliumEndpoint(ep *types.CiliumEndpoint) error {
	if ep.Networking != nil {
		namedPortsChanged := false
		for _, pair := range ep.Networking.Addressing {
			if pair.IPV4 != "" {
				portsChanged := s.ipc.DeleteOnMetadataMatch(pair.IPV4, source.CustomResource, ep.Namespace, ep.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}

			if pair.IPV6 != "" {
				portsChanged := s.ipc.DeleteOnMetadataMatch(pair.IPV6, source.CustomResource, ep.Namespace, ep.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}
		}
		if namedPortsChanged {
			s.pt.TriggerPolicyUpdates(true, "Named ports deleted")
		}
	}
	return nil
}

func New(pt policyTriggerer, ipc *ipcache.IPCache) *Subscriber {
	return &Subscriber{
		pt:  pt,
		ipc: ipc,
	}
}

type Subscriber struct {
	pt  policyTriggerer
	ipc *ipcache.IPCache
}

type policyTriggerer interface {
	TriggerPolicyUpdates(bool, string)
}
