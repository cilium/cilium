// Copyright 2021 Authors of Cilium
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

// This package contains the agent code used to configure the Wireguard tunnel
// between nodes. The code supports adding and removing peers at run-time
// and the peer information is retrieved via the CiliumNode object.
package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/wireguard/types"

	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	listenPort = 51871
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "wireguard")

// wireguardClient is an interface to mock wgctrl.Client
type wireguardClient interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

// Agent needs to be initialized with Init(). In Init(), the Wireguard tunnel
// device will be created and the proper routes set.  During Init(), existing
// peer keys are placed into `restoredPubKeys`.  Once RestoreFinished() is
// called obsolete keys and peers are removed.  UpdatePeer() inserts or updates
// the public key of peer discovered via the node manager.
type Agent struct {
	lock.RWMutex
	wgClient         wireguardClient
	ipCache          *ipcache.IPCache
	listenPort       int
	privKey          wgtypes.Key
	peerByNodeName   map[string]*peerConfig
	nodeNameByNodeIP map[string]string
	restoredPubKeys  map[wgtypes.Key]struct{}
}

// NewAgent creates a new Wireguard Agent
func NewAgent(privKeyPath string) (*Agent, error) {
	key, err := loadOrGeneratePrivKey(privKeyPath)
	if err != nil {
		return nil, err
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	node.SetWireguardPubKey(key.PublicKey().String())

	return &Agent{
		wgClient:         wgClient,
		ipCache:          ipcache.IPIdentityCache,
		privKey:          key,
		listenPort:       listenPort,
		peerByNodeName:   map[string]*peerConfig{},
		nodeNameByNodeIP: map[string]string{},
		restoredPubKeys:  map[wgtypes.Key]struct{}{},
	}, nil
}

// Close is called when the agent stops
func (a *Agent) Close() error {
	return a.wgClient.Close()
}

// Init is called after we have obtained a local Wireguard IP
func (a *Agent) Init(mtuConfig mtu.Configuration) error {
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: types.IfaceName}}
	err := netlink.LinkAdd(link)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		if errors.Is(err, unix.EOPNOTSUPP) {
			return fmt.Errorf("wireguard not supported by the Linux kernel (netlink: %w). "+
				"Please upgrade your kernel or manually install the kernel module: "+
				"https://www.wireguard.com/install/", err)
		}
		return err
	}

	if option.Config.EnableIPv4 {
		if err := sysctl.Disable(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", types.IfaceName)); err != nil {
			return nil
		}
	}

	cfg := wgtypes.Config{
		PrivateKey:   &a.privKey,
		ListenPort:   &a.listenPort,
		ReplacePeers: false,
	}
	if err := a.wgClient.ConfigureDevice(types.IfaceName, cfg); err != nil {
		return err
	}

	linkMTU := mtuConfig.GetDeviceMTU() - mtu.WireguardOverhead
	if err := netlink.LinkSetMTU(link, linkMTU); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	dev, err := a.wgClient.Device(types.IfaceName)
	if err != nil {
		return err
	}
	for _, peer := range dev.Peers {
		a.restoredPubKeys[peer.PublicKey] = struct{}{}
	}

	// Create the rule to steer the marked traffic (from a local endpoint to a
	// remote endpoint) via the Wireguard tunnel
	rule := route.Rule{
		Priority: linux_defaults.RulePriorityWireguard,
		Mark:     linux_defaults.RouteMarkEncrypt,
		Mask:     linux_defaults.RouteMarkMask,
		Table:    linux_defaults.RouteTableWireguard,
	}
	rt := route.Route{
		Device: types.IfaceName,
		Table:  linux_defaults.RouteTableWireguard,
	}
	if option.Config.EnableIPv4 {
		if err := route.ReplaceRule(rule); err != nil {
			return err
		}

		subnet := net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, net.IPv4len),
		}
		rt.Prefix = subnet
		if _, err := route.Upsert(rt); err != nil {
			return err
		}
	}
	if option.Config.EnableIPv6 {
		if err := route.ReplaceRuleIPv6(rule); err != nil {
			return err
		}

		subnet := net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, net.IPv6len),
		}
		rt.Prefix = subnet
		if _, err := route.Upsert(rt); err != nil {
			return err
		}
	}

	a.ipCache.AddListener(a)

	return nil
}

func (a *Agent) RestoreFinished() error {
	a.Lock()
	defer a.Unlock()

	// Delete obsolete peers
	for _, p := range a.peerByNodeName {
		delete(a.restoredPubKeys, p.pubKey)
	}
	for pubKey := range a.restoredPubKeys {
		log.WithField(logfields.PubKey, pubKey).Info("Removing obsolete peer")
		if err := a.deletePeerByPubKey(pubKey); err != nil {
			return err
		}
	}

	a.restoredPubKeys = nil

	log.Debug("Finished restore")

	return nil
}

func (a *Agent) UpdatePeer(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error {
	// To avoid running into a deadlock, we need to lock the IPCache before
	// calling a.Lock(), because IPCache might try to call into
	// OnIPIdentityCacheChange concurrently
	a.ipCache.RLock()
	defer a.ipCache.RUnlock()

	a.Lock()
	defer a.Unlock()

	var allowedIPs []net.IPNet = nil
	if prev := a.peerByNodeName[nodeName]; prev != nil {
		// Handle pubKey change
		if prev.pubKey.String() != pubKeyHex {
			log.WithField(logfields.NodeName, nodeName).Debug("Pubkey has changed")
			// pubKeys differ, so delete old peer
			if err := a.deletePeerByPubKey(prev.pubKey); err != nil {
				return err
			}
		}

		// Reuse allowedIPs from existing peer config
		allowedIPs = prev.allowedIPs

		// Handle Node IP change
		if !prev.nodeIPv4.Equal(nodeIPv4) {
			delete(a.nodeNameByNodeIP, prev.nodeIPv4.String())
			allowedIPs = nil // reset allowedIPs and re-initialize below
		}
		if !prev.nodeIPv6.Equal(nodeIPv6) {
			delete(a.nodeNameByNodeIP, prev.nodeIPv6.String())
			allowedIPs = nil // reset allowedIPs and re-initialize below
		}
	}

	if allowedIPs == nil {
		// (Re-)Initialize the allowedIPs list by querying the IPCache. The
		// allowedIPs will be updated by OnIPIdentityCacheChange after this
		// function returns.
		var lookupIPv4, lookupIPv6 net.IP
		if option.Config.EnableIPv4 && nodeIPv4 != nil {
			lookupIPv4 = nodeIPv4
		}
		if option.Config.EnableIPv6 && nodeIPv6 != nil {
			lookupIPv6 = nodeIPv6
		}
		allowedIPs = append(allowedIPs, a.ipCache.LookupByHostRLocked(lookupIPv4, lookupIPv6)...)
	}

	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

	ep := ""
	if option.Config.EnableIPv4 && nodeIPv4 != nil {
		ep = net.JoinHostPort(nodeIPv4.String(), strconv.Itoa(listenPort))
	} else if option.Config.EnableIPv6 && nodeIPv6 != nil {
		ep = net.JoinHostPort(nodeIPv6.String(), strconv.Itoa(listenPort))
	} else {
		return fmt.Errorf("missing node IP for node %q", nodeName)
	}

	epAddr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return fmt.Errorf("failed to resolve peer endpoint address: %w", err)
	}

	peer := &peerConfig{
		pubKey:     pubKey,
		endpoint:   epAddr,
		nodeIPv4:   nodeIPv4,
		nodeIPv6:   nodeIPv6,
		allowedIPs: allowedIPs,
	}

	log.WithFields(logrus.Fields{
		logfields.NodeName: nodeName,
		logfields.PubKey:   pubKeyHex,
		logfields.NodeIPv4: nodeIPv4,
		logfields.NodeIPv6: nodeIPv6,
	}).Debug("Updating peer")

	if err := a.updatePeerByConfig(peer); err != nil {
		return err
	}

	a.peerByNodeName[nodeName] = peer
	if nodeIPv4 != nil {
		a.nodeNameByNodeIP[nodeIPv4.String()] = nodeName
	}
	if nodeIPv6 != nil {
		a.nodeNameByNodeIP[nodeIPv6.String()] = nodeName
	}

	return nil
}

func (a *Agent) DeletePeer(nodeName string) error {
	a.Lock()
	defer a.Unlock()

	peer := a.peerByNodeName[nodeName]
	if peer == nil {
		return fmt.Errorf("cannot find peer for %q node", nodeName)
	}

	if err := a.deletePeerByPubKey(peer.pubKey); err != nil {
		return err
	}

	delete(a.peerByNodeName, nodeName)
	if peer.nodeIPv4 != nil {
		delete(a.nodeNameByNodeIP, peer.nodeIPv4.String())
	}
	if peer.nodeIPv6 != nil {
		delete(a.nodeNameByNodeIP, peer.nodeIPv6.String())
	}

	return nil
}

func (a *Agent) deletePeerByPubKey(pubKey wgtypes.Key) error {
	log.WithField(logfields.PubKey, pubKey).Debug("Removing peer")

	peerCfg := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	cfg := &wgtypes.Config{Peers: []wgtypes.PeerConfig{peerCfg}}
	if err := a.wgClient.ConfigureDevice(types.IfaceName, *cfg); err != nil {
		return err
	}

	return nil
}

// updatePeerByConfig updates the Wireguard kernel peer config based on peerConfig p
func (a *Agent) updatePeerByConfig(p *peerConfig) error {
	peer := wgtypes.PeerConfig{
		PublicKey:         p.pubKey,
		Endpoint:          p.endpoint,
		AllowedIPs:        p.allowedIPs,
		ReplaceAllowedIPs: true,
	}

	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peer},
	}

	log.WithFields(logrus.Fields{
		logfields.Endpoint: p.endpoint,
		logfields.PubKey:   p.pubKey,
		logfields.IPAddrs:  p.allowedIPs,
	}).Debug("Updating peer config")

	return a.wgClient.ConfigureDevice(types.IfaceName, cfg)
}

func loadOrGeneratePrivKey(filePath string) (key wgtypes.Key, err error) {
	bytes, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("failed to generate wg private key: %w", err)
		}

		err = os.WriteFile(filePath, key[:], 0600)
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("failed to save wg private key: %w", err)
		}

		return key, nil
	} else if err != nil {
		return wgtypes.Key{}, fmt.Errorf("failed to load wg private key: %w", err)
	}

	return wgtypes.NewKey(bytes)
}

// OnIPIdentityCacheChange implements ipcache.IPIdentityMappingListener
func (a *Agent) OnIPIdentityCacheChange(modType ipcache.CacheModification, ipnet net.IPNet, oldHostIP, newHostIP net.IP,
	_ *ipcache.Identity, _ ipcache.Identity, _ uint8, _ *ipcache.K8sMetadata) {

	// This function is invoked from the IPCache with the
	// ipcache.IPIdentityCache lock held. We therefore need to be careful when
	// calling into ipcache.IPIdentityCache from Agent to avoid potential
	// deadlocks.
	a.Lock()
	defer a.Unlock()

	// We are only interested in IPCache entries where the hostIP is set, i.e.
	// updates with oldHostIP set for deleted entries and newHostIP set
	// for newly created entries. Entries without a hostIP
	// (e.g. remote identities) are not relevant for Wireguard's allowedIPs.
	//
	// If we do not find a Wireguard peer for a given hostIP, we intentionally
	// ignore the IPCache upserts here. We instead assume that UpdatePeer() will
	// eventually be called once a node starts participating in Wireguard
	// (or if its host IP changed). UpdatePeer initializes the allowedIPs
	// of newly discovered hostIPs by querying the IPCache, which will contain
	// all updates we might have skipped here before the hostIP was known.
	var updatedPeer *peerConfig
	switch {
	case modType == ipcache.Delete && oldHostIP != nil:
		if nodeName, ok := a.nodeNameByNodeIP[oldHostIP.String()]; ok {
			if peer := a.peerByNodeName[nodeName]; peer != nil {
				if peer.removeAllowedIP(ipnet) {
					updatedPeer = peer
				}
			}
		}
	case modType == ipcache.Upsert && newHostIP != nil:
		if nodeName, ok := a.nodeNameByNodeIP[newHostIP.String()]; ok {
			if peer := a.peerByNodeName[nodeName]; peer != nil {
				if peer.insertAllowedIP(ipnet) {
					updatedPeer = peer
				}
			}
		}
	}

	if updatedPeer != nil {
		if err := a.updatePeerByConfig(updatedPeer); err != nil {
			log.WithFields(logrus.Fields{
				logfields.Modification: modType,
				logfields.IPAddr:       ipnet.String(),
				logfields.OldNode:      oldHostIP,
				logfields.NewNode:      newHostIP,
				logfields.PubKey:       updatedPeer.pubKey,
			}).WithError(err).
				Error("Failed to update Wireguard peer after ipcache update")
		}
	}
}

// OnIPIdentityCacheGC implements ipcache.IPIdentityMappingListener
func (a *Agent) OnIPIdentityCacheGC() {
	// ignored
}

// Status returns the state of the Wireguard tunnel managed by this instance.
// If withPeers is true, then the details about each connected peer are
// are populated as well.
func (a *Agent) Status(withPeers bool) (*models.WireguardStatus, error) {
	a.Lock()
	dev, err := a.wgClient.Device(types.IfaceName)
	a.Unlock()

	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	var peers []*models.WireguardPeer
	if withPeers {
		peers = make([]*models.WireguardPeer, 0, len(dev.Peers))
		for _, p := range dev.Peers {
			allowedIPs := make([]string, 0, len(p.AllowedIPs))
			for _, ip := range p.AllowedIPs {
				allowedIPs = append(allowedIPs, ip.String())
			}

			peer := &models.WireguardPeer{
				PublicKey:         p.PublicKey.String(),
				Endpoint:          p.Endpoint.String(),
				LastHandshakeTime: strfmt.DateTime(p.LastHandshakeTime),
				AllowedIps:        allowedIPs,
			}
			peers = append(peers, peer)
		}
	}

	status := &models.WireguardStatus{
		Interfaces: []*models.WireguardInterface{{
			Name:       dev.Name,
			ListenPort: int64(dev.ListenPort),
			PublicKey:  dev.PublicKey.String(),
			PeerCount:  int64(len(dev.Peers)),
			Peers:      peers,
		}},
	}

	return status, nil
}

// peerConfig represents the kernel state of each Wireguard peer.
// In order to be able to add and remove individual IPs from the
//`AllowedIPs` list, we store a `peerConfig` for each known Wireguard peer.
// When a peer is first discovered via node manager, we obtain the remote
// peers `AllowedIPs` by querying Cilium's user-space copy of the IPCache
// in the agent. In addition, we also subscribe to IPCache updates in the
// Wireguard agent and update the `AllowedIPs` list of known peers
// accordingly.
type peerConfig struct {
	pubKey             wgtypes.Key
	endpoint           *net.UDPAddr
	nodeIPv4, nodeIPv6 net.IP
	allowedIPs         []net.IPNet
}

// removeAllowedIP removes ip from the list of allowedIPs and returns true
// if the list of allowedIPs changed
func (p *peerConfig) removeAllowedIP(ip net.IPNet) (updated bool) {
	filtered := p.allowedIPs[:0]
	for _, allowedIP := range p.allowedIPs {
		if cidr.Equal(&allowedIP, &ip) {
			updated = true
		} else {
			filtered = append(filtered, allowedIP)
		}
	}

	p.allowedIPs = filtered
	return updated
}

// insertAllowedIP inserts ip into the list of allowedIPs and returns true
// if the list of allowedIPs changed
func (p *peerConfig) insertAllowedIP(ip net.IPNet) (updated bool) {
	for _, allowedIP := range p.allowedIPs {
		if cidr.Equal(&allowedIP, &ip) {
			return false
		}
	}

	p.allowedIPs = append(p.allowedIPs, ip)
	return true
}
