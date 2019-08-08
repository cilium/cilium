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

package linux

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/endpoint/connector"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/sirupsen/logrus"
)

// DatapathConfiguration is the static configuration of the datapath. The
// configuration cannot change throughout the lifetime of a datapath object.
type DatapathConfiguration struct {
	// HostDevice is the name of the device to be used to access the host.
	HostDevice string
	// EncryptInterface is the name of the device to be used for direct ruoting encryption
	EncryptInterface string
}

type linuxDatapath struct {
	node           datapath.NodeHandler
	nodeAddressing datapath.NodeAddressing
	config         DatapathConfiguration
	lxcMap         *lxcmap.LXCMap
}

// NewDatapath creates a new Linux datapath
func NewDatapath(config DatapathConfiguration) datapath.Datapath {
	dp := &linuxDatapath{
		nodeAddressing: NewNodeAddressing(),
		config:         config,
	}

	dp.node = NewNodeHandler(config, dp.nodeAddressing)

	if err := bpf.ConfigureResourceLimits(); err != nil {
		log.WithError(err).Fatal("Unable to set memory resource limits")
	}

	dp.lxcMap = lxcmap.NewMap(lxcmap.MapName)
	if _, err := dp.lxcMap.OpenOrCreate(); err != nil {
		log.WithError(err).Fatal("unable to initialize LXCMap")
	}

	if !option.Config.RestoreState {
		// If we are not restoring state, all endpoints can be
		// deleted. Entries will be re-populated.
		dp.lxcMap.DeleteAll()
	}

	if config.EncryptInterface != "" {
		if err := connector.DisableRpFilter(config.EncryptInterface); err != nil {
			log.WithField(logfields.Interface, config.EncryptInterface).Warn("Rpfilter could not be disabled, node to node encryption may fail")
		}
	}

	return dp
}

// Node returns the handler for node events
func (l *linuxDatapath) Node() datapath.NodeHandler {
	return l.node
}

// LocalNodeAddressing returns the node addressing implementation of the local
// node
func (l *linuxDatapath) LocalNodeAddressing() datapath.NodeAddressing {
	return l.nodeAddressing
}

func (l *linuxDatapath) InstallProxyRules(proxyPort uint16, ingress bool, name string) error {
	return iptables.InstallProxyRules(proxyPort, ingress, name)
}

func (l *linuxDatapath) RemoveProxyRules(proxyPort uint16, ingress bool, name string) error {
	return iptables.RemoveProxyRules(proxyPort, ingress, name)
}

func (l *linuxDatapath) WriteEndpoint(frontend datapath.EndpointFrontend) error {
	return l.lxcMap.WriteEndpoint(frontend)
}

// SyncLXCMap adds local host entries to bpf lxcmap, as well as ipcache, if
// needed, and also notifies the daemon and network policy hosts cache if
// changes were made.
func (l *linuxDatapath) SyncEndpointsAndHostIPs() error {
	specialIdentities := l.aggregateSpecialIdentities()

	existingEndpoints, err := l.lxcMap.Dump2()
	if err != nil {
		return err
	}

	for _, ipIDPair := range specialIdentities {
		hostKey := node.GetIPsecKeyIdentity()
		isHost := ipIDPair.ID == identity.ReservedIdentityHost
		if isHost {
			added, err := l.lxcMap.SyncHostEntry(ipIDPair.IP)
			if err != nil {
				return fmt.Errorf("Unable to add host entry to endpoint map: %s", err)
			}
			if added {
				log.WithField(logfields.IPAddr, ipIDPair.IP).Debugf("Added local ip to endpoint map")
			}
		}

		delete(existingEndpoints, ipIDPair.IP.String())

		// Upsert will not propagate (reserved:foo->ID) mappings across the cluster,
		// and we specifically don't want to do so.
		ipcache.IPIdentityCache.Upsert(ipIDPair.PrefixString(), nil, hostKey, ipcache.Identity{
			ID:     ipIDPair.ID,
			Source: source.Local,
		})
	}

	for hostIP, info := range existingEndpoints {
		if ip := net.ParseIP(hostIP); info.IsHost() && ip != nil {
			if err := l.lxcMap.DeleteEntry(ip); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.IPAddr: hostIP,
				}).Warn("Unable to delete obsolete host IP from BPF map")
			} else {
				log.Debugf("Removed outdated host ip %s from endpoint map", hostIP)
			}

			ipcache.IPIdentityCache.Delete(hostIP, source.Local)
		}
	}

	return nil
}


func (l *linuxDatapath) aggregateSpecialIdentities()[]identity.IPIdentityPair {
	specialIdentities := []identity.IPIdentityPair{}

	if option.Config.EnableIPv4 {
		addrs, err := l.LocalNodeAddressing().IPv4().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv4 addresses")
		}

		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities,
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.ReservedIdentityHost,
					})
			}
		}

		specialIdentities = append(specialIdentities,
			identity.IPIdentityPair{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, net.IPv4len*8),
				ID:   identity.ReservedIdentityWorld,
			})
	}

	if option.Config.EnableIPv6 {
		addrs, err := l.LocalNodeAddressing().IPv6().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv4 addresses")
		}

		addrs = append(addrs, node.GetIPv6Router())
		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities,
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.ReservedIdentityHost,
					})
			}
		}

		specialIdentities = append(specialIdentities,
			identity.IPIdentityPair{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, net.IPv6len*8),
				ID:   identity.ReservedIdentityWorld,
			})
	}
	return specialIdentities
}


func (l *linuxDatapath) DeleteElement(frontend datapath.EndpointFrontend) []error {
	return l.lxcMap.DeleteElement(frontend)
}

func (l *linuxDatapath) DeleteEntry(ip net.IP) error {
	return l.lxcMap.DeleteEntry(ip)
}

func (l *linuxDatapath) DumpToMap() (datapath.ExistingEndpointsState, error) {
	return l.lxcMap.DumpToMap()
}
