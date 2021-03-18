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
	"net"
	"os"
	"strconv"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/wireguard/types"

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

// Agent needs to be initialized with Init() after the local Wireguard node IP
// is known. In .Init(), the Wireguard tunnel device will be created
// and the proper routes set.
// During Init(), existing peer keys are placed into `restoredPubKeys`.
// Once RestoreFinished() is called obsolete keys and peers are removed.
// UpdatePeer() inserts or updates the public key of peer discovered via
// the node manager.
type Agent struct {
	lock.RWMutex
	wgClient         *wgctrl.Client
	listenPort       int
	privKey          wgtypes.Key
	wireguardV4CIDR  *net.IPNet
	wireguardV6CIDR  *net.IPNet
	pubKeyByNodeName map[string]string // nodeName => pubKey
	restoredPubKeys  map[string]struct{}
}

// NewAgent creates a new Wireguard Agent
func NewAgent(privKeyPath string, wgV4Net, wgV6Net *net.IPNet) (*Agent, error) {
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
		privKey:          key,
		wireguardV4CIDR:  wgV4Net,
		wireguardV6CIDR:  wgV6Net,
		listenPort:       listenPort,
		pubKeyByNodeName: map[string]string{},
		restoredPubKeys:  map[string]struct{}{},
	}, nil
}

// Close is called when the agent stops
func (a *Agent) Close() error {
	return a.wgClient.Close()
}

// Init is called after we have obtained a local Wireguard IP
func (a *Agent) Init() error {
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: types.IfaceName}}
	err := netlink.LinkAdd(link)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}

	if !option.Config.EnableIPv4 {
		if err := sysctl.Write(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", types.IfaceName), "2"); err != nil {
			return nil
		}
	}

	type ipNetFamily struct {
		ip     *net.IPNet
		family int
	}
	wireguardIPs := []ipNetFamily{}
	if option.Config.EnableIPv4 {
		ip := &net.IPNet{
			IP:   node.GetWireguardIPv4(),
			Mask: a.wireguardV4CIDR.Mask,
		}
		wireguardIPs = append(wireguardIPs, ipNetFamily{ip: ip, family: netlink.FAMILY_V4})
	}
	if option.Config.EnableIPv6 {
		ip := &net.IPNet{
			IP:   node.GetWireguardIPv6(),
			Mask: a.wireguardV6CIDR.Mask,
		}
		wireguardIPs = append(wireguardIPs, ipNetFamily{ip: ip, family: netlink.FAMILY_V6})
	}
	for _, p := range wireguardIPs {
		// Removes stale IP addresses from wg device
		addrs, err := netlink.AddrList(link, p.family)
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			if !cidr.NewCIDR(addr.IPNet).Equal(cidr.NewCIDR(p.ip)) {
				if err := netlink.AddrDel(link, &addr); err != nil {
					return fmt.Errorf("failed to remove stale wg ip: %w", err)
				}
			}
		}

		err = netlink.AddrAdd(link, &netlink.Addr{IPNet: p.ip})
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return err
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

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	dev, err := a.wgClient.Device(types.IfaceName)
	if err != nil {
		return err
	}
	for _, peer := range dev.Peers {
		a.restoredPubKeys[peer.PublicKey.String()] = struct{}{}
	}

	// Create the rule to steer the marked traffic (from a local endpoint to a
	// remote endpoint) via the Wireguard tunnel
	rule := route.Rule{
		Priority: linux_defaults.RulePriorityWireguard,
		Mark:     linux_defaults.RouteMarkEncrypt,
		Mask:     linux_defaults.RouteMarkMask,
		Table:    linux_defaults.RouteTableWireguard,
	}
	if err := route.ReplaceRule(rule); err != nil {
		return err
	}

	subnet := net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.CIDRMask(0, net.IPv4len),
	}
	rt := route.Route{
		Prefix: subnet,
		Device: types.IfaceName,
		Table:  linux_defaults.RouteTableWireguard,
	}
	if _, err := route.Upsert(rt); err != nil {
		return err
	}

	return nil
}

func (a *Agent) RestoreFinished() error {
	a.Lock()
	defer a.Unlock()

	// Delete obsolete peers
	for _, pubKeyHex := range a.pubKeyByNodeName {
		delete(a.restoredPubKeys, pubKeyHex)
	}
	for pubKeyHex := range a.restoredPubKeys {
		log.WithField(logfields.PubKey, pubKeyHex).Info("Removing obsolete peer")
		if err := a.deletePeerByPubKey(pubKeyHex); err != nil {
			return err
		}
	}

	a.restoredPubKeys = nil

	log.Info("Finished restore")

	return nil
}

func (a *Agent) UpdatePeer(nodeName, pubKeyHex string,
	wgIPv4, nodeIPv4 net.IP, podCIDRv4 *net.IPNet,
	wgIPv6, nodeIPv6 net.IP, podCIDRv6 *net.IPNet) error {

	a.Lock()
	defer a.Unlock()

	// Handle pubKey change
	if prevPubKeyHex, found := a.pubKeyByNodeName[nodeName]; found && prevPubKeyHex != pubKeyHex {
		log.WithField(logfields.NodeName, nodeName).Info("Pubkey has changed")
		// pubKeys differ, so delete old peer
		if err := a.deletePeerByPubKey(prevPubKeyHex); err != nil {
			return err
		}
		delete(a.pubKeyByNodeName, nodeName)
	}

	log.WithFields(logrus.Fields{
		logfields.NodeName:  nodeName,
		logfields.PubKey:    pubKeyHex,
		logfields.NodeIPv4:  nodeIPv4,
		logfields.PodCIDRv4: podCIDRv4,
		logfields.WgIPv4:    wgIPv4,
		logfields.NodeIPv6:  nodeIPv6,
		logfields.PodCIDRv6: podCIDRv6,
		logfields.WgIPv6:    wgIPv6,
	}).Info("Adding peer")

	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

	allowedIPs := []net.IPNet{}

	if option.Config.EnableIPv4 {
		if wgIPv4 != nil {
			var peerIPNet net.IPNet
			peerIPNet.IP = wgIPv4
			peerIPNet.Mask = net.IPv4Mask(255, 255, 255, 255)
			allowedIPs = append(allowedIPs, peerIPNet)
		}
		if podCIDRv4 != nil {
			allowedIPs = append(allowedIPs, *podCIDRv4)
		}
	}
	if option.Config.EnableIPv6 {
		if wgIPv6 != nil {
			var peerIPNet net.IPNet
			peerIPNet.IP = wgIPv6
			peerIPNet.Mask = net.CIDRMask(128, 128)
			allowedIPs = append(allowedIPs, peerIPNet)
		}
		if podCIDRv6 != nil {
			allowedIPs = append(allowedIPs, *podCIDRv6)
		}
	}

	ep := ""
	if option.Config.EnableIPv4 {
		ep = net.JoinHostPort(nodeIPv4.String(), strconv.Itoa(listenPort))
	} else if option.Config.EnableIPv6 {
		ep = net.JoinHostPort(nodeIPv6.String(), strconv.Itoa(listenPort))
	}
	epAddr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return err
	}

	peerConfig := wgtypes.PeerConfig{
		Endpoint:          epAddr,
		PublicKey:         pubKey,
		AllowedIPs:        allowedIPs,
		ReplaceAllowedIPs: true,
	}
	cfg := &wgtypes.Config{ReplacePeers: false, Peers: []wgtypes.PeerConfig{peerConfig}}
	if err := a.wgClient.ConfigureDevice(types.IfaceName, *cfg); err != nil {
		return err
	}

	a.pubKeyByNodeName[nodeName] = pubKeyHex

	return nil
}

func (a *Agent) DeletePeer(nodeName string) error {
	a.Lock()
	defer a.Unlock()

	pubKeyHex, found := a.pubKeyByNodeName[nodeName]
	if !found {
		return fmt.Errorf("cannot find pubkey for %s node", nodeName)
	}

	if err := a.deletePeerByPubKey(pubKeyHex); err != nil {
		return err
	}

	delete(a.pubKeyByNodeName, nodeName)

	return nil
}

func (a *Agent) deletePeerByPubKey(pubKeyHex string) error {
	log.WithField(logfields.PubKey, pubKeyHex).Info("Removing peer")

	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

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
