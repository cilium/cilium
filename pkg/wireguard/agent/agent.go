// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This package contains the agent code used to configure the WireGuard tunnel
// between nodes. The code supports adding and removing peers at run-time
// and the peer information is retrieved via the CiliumNode object.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/go-openapi/strfmt"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	k8sLabels "k8s.io/apimachinery/pkg/labels"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/wireguard/types"
)

var (
	subsysLogAttr  = []any{logfields.LogSubsys, "wireguard"}
	wgDummyPeerKey = wgtypes.Key{}
)

// wireguardClient is an interface to mock wgctrl.Client
type wireguardClient interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

// Agent needs to be initialized with Init(). In Init(), the WireGuard tunnel
// device will be created and the proper routes set. Once RestoreFinished() is
// called, obsolete keys and peers, as well as stale AllowedIPs are removed.
// UpdatePeer() inserts or updates the public key of peers discovered via the
// node manager.
type Agent struct {
	logger *slog.Logger

	lock.RWMutex

	wgClient    wireguardClient
	ipCache     *ipcache.IPCache
	listenPort  int
	privKey     wgtypes.Key
	privKeyPath string
	sysctl      sysctl.Sysctl
	jobGroup    job.Group
	db          *statedb.DB
	mtuTable    statedb.Table[mtu.RouteMTU]

	peerByNodeName   map[string]*peerConfig
	nodeNameByNodeIP map[string]string
	nodeNameByPubKey map[wgtypes.Key]string

	// initialized in InitLocalNodeFromWireGuard
	optOut bool
	// initialized in NewAgent to subscribe or not to IPCache events.
	needIPCacheEvents bool
}

// NewAgent creates a new WireGuard Agent
func NewAgent(rootLogger *slog.Logger, privKeyPath string, sysctl sysctl.Sysctl, jobGroup job.Group, db *statedb.DB, mtuTable statedb.Table[mtu.RouteMTU]) (*Agent, error) {
	// In tunneling mode we only need nodeIPs, which are always inserted in UpdatePeer.
	// Therefore, we sync IPs from IPCache only in native routing mode
	// or when the fallback flag WireguardTrackAllIPsFallback is enabled.
	var needIPCacheEvents bool
	if !option.Config.TunnelingEnabled() || option.Config.WireguardTrackAllIPsFallback {
		needIPCacheEvents = true
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &Agent{
		logger:      rootLogger.With(subsysLogAttr...),
		wgClient:    wgClient,
		privKeyPath: privKeyPath,
		listenPort:  types.ListenPort,
		sysctl:      sysctl,
		jobGroup:    jobGroup,
		db:          db,
		mtuTable:    mtuTable,

		peerByNodeName:   map[string]*peerConfig{},
		nodeNameByNodeIP: map[string]string{},
		nodeNameByPubKey: map[wgtypes.Key]string{},

		needIPCacheEvents: needIPCacheEvents,
	}, nil
}

// Start implements cell.HookInterface.
func (a *Agent) Start(cell.HookContext) (err error) {
	a.privKey, err = loadOrGeneratePrivKey(a.privKeyPath)
	return
}

// Stop implements cell.HookInterface.
func (a *Agent) Stop(cell.HookContext) error {
	a.RLock()
	defer a.RUnlock()

	return a.wgClient.Close()
}

var _ cell.HookInterface = &Agent{}

func (a *Agent) Name() string {
	return "wireguard-agent"
}

// InitLocalNodeFromWireGuard configures the fields on the local node. Called from
// the LocalNodeSynchronizer _before_ the local node is published in the K8s
// CiliumNode CRD or the kvstore.
//
// This method does the following:
//   - It sets the local WireGuard public key (to be read by other nodes).
//   - It reads the local node's labels to determine if the local node wants to
//     opt-out of node-to-node encryption.
//   - If the local node opts out of node-to-node encryption, we set the
//     localNode.EncryptKey to zero. This indicates to other nodes that they
//     should not encrypt node-to-node traffic with us.
func (a *Agent) InitLocalNodeFromWireGuard(localNode *node.LocalNode) {
	a.Lock()
	defer a.Unlock()

	a.logger.Debug("Initializing local node store with WireGuard public key and settings")

	localNode.EncryptionKey = types.StaticEncryptKey
	localNode.WireguardPubKey = a.privKey.PublicKey().String()
	localNode.Annotations[annotation.WireguardPubKey] = localNode.WireguardPubKey

	if option.Config.EncryptNode && option.Config.NodeEncryptionOptOutLabels.Matches(k8sLabels.Set(localNode.Labels)) {
		a.logger.Info(
			"Opting out from node-to-node encryption on this node as per "+
				option.NodeEncryptionOptOutLabels+" label selector",
			logfields.Selector, option.Config.NodeEncryptionOptOutLabels,
		)
		localNode.OptOutNodeEncryption = true
		localNode.EncryptionKey = 0
	}

	a.optOut = localNode.OptOutNodeEncryption
}

// Init creates and configures the local WireGuard tunnel device.
func (a *Agent) Init(ipcache *ipcache.IPCache) error {
	addIPCacheListener := false
	a.Lock()
	a.ipCache = ipcache
	defer func() {
		// IPCache will call back into OnIPIdentityCacheChange which requires
		// us to release a.mutex before we can add ourself as a listener.
		a.Unlock()
		if addIPCacheListener && a.needIPCacheEvents {
			a.ipCache.AddListener(a)
		}
	}()

	var mtuConfig mtu.RouteMTU
	for {
		var (
			found bool
			watch <-chan struct{}
		)
		mtuConfig, _, watch, found = a.mtuTable.GetWatch(a.db.ReadTxn(), mtu.MTURouteIndex.Query(mtu.DefaultPrefixV4))
		if found {
			break
		}
		<-watch
	}

	linkMTU := mtuConfig.DeviceMTU - mtu.WireguardOverhead

	// try to remove any old tun devices created by userspace mode
	link, _ := safenetlink.LinkByName(types.IfaceName)
	if _, isTuntap := link.(*netlink.Tuntap); isTuntap {
		_ = netlink.LinkDel(link)
	}

	link = &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: types.IfaceName,
			MTU:  linkMTU,
		},
	}

	err := netlink.LinkAdd(link)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		if !errors.Is(err, unix.EOPNOTSUPP) {
			return fmt.Errorf("failed to add WireGuard device: %w", err)
		}

		return fmt.Errorf("WireGuard not supported by the Linux kernel (netlink: %w). "+
			"Please upgrade your kernel, or manually install the kernel module "+
			"(https://www.wireguard.com/install/)", err)
	}

	if option.Config.EnableIPv4 {
		if err := a.sysctl.Disable([]string{"net", "ipv4", "conf", types.IfaceName, "rp_filter"}); err != nil {
			return fmt.Errorf("failed to disable rp_filter: %w", err)
		}
	}

	fwMark := linux_defaults.MagicMarkWireGuardEncrypted
	cfg := wgtypes.Config{
		PrivateKey:   &a.privKey,
		ListenPort:   &a.listenPort,
		ReplacePeers: false,
		FirewallMark: &fwMark,
		Peers:        nil,
	}
	if err := a.wgClient.ConfigureDevice(types.IfaceName, cfg); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %w", err)
	}

	// set MTU again explicitly in case we are re-using an existing device
	if err := netlink.LinkSetMTU(link, linkMTU); err != nil {
		return fmt.Errorf("failed to set mtu: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set link up: %w", err)
	}

	a.jobGroup.Add(job.OneShot("mtu-reconciler", a.mtuReconciler))

	// this is read by the defer statement above
	addIPCacheListener = true

	return nil
}

// mtuReconciler is a job that reconciles changes to the MTU to the WireGuard interface.
// If an error is encountered, the job will retry with exponential backoff.
func (a *Agent) mtuReconciler(ctx context.Context, health cell.Health) error {
	retryTimer := backoff.Exponential{Logger: a.logger, Min: 100 * time.Millisecond, Max: 1 * time.Minute}
	retry := false
	for {
		mtuRoute, _, watch, found := a.mtuTable.GetWatch(a.db.ReadTxn(), mtu.MTURouteIndex.Query(mtu.DefaultPrefixV4))
		if found {
			link, err := safenetlink.LinkByName(types.IfaceName)
			if err != nil {
				health.Degraded("failed to get WireGuard link", err)
				retry = true
				goto next
			}

			linkMTU := mtuRoute.DeviceMTU - mtu.WireguardOverhead

			if link.Attrs().MTU != linkMTU {
				if err = netlink.LinkSetMTU(link, linkMTU); err != nil {
					health.Degraded("failed to set WireGuard link mtu", err)
					retry = true
					goto next
				}
			}

			health.OK(fmt.Sprintf("OK (%d)", linkMTU))
		}

		retryTimer.Reset()
		retry = false

	next:
		if retry {
			if err := retryTimer.Wait(ctx); err != nil {
				return nil
			}
		} else {
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			}
		}
	}
}

func (a *Agent) RestoreFinished(cm *clustermesh.ClusterMesh) error {
	if cm != nil {
		// Wait until we received the initial list of nodes from all remote clusters,
		// otherwise we might remove valid peers and disrupt existing connections.
		cm.NodesSynced(context.Background())
		// Additionally wait for ipcache synchronization, so that we don't garbage
		// collect non-stale AllowedIPs too early.
		cm.IPIdentitiesSynced(context.Background())
	}

	a.Lock()
	defer a.Unlock()

	// Delete obsolete peers
	pubKeyToPeerConfig := make(map[wgtypes.Key]*peerConfig)
	for _, peer := range a.peerByNodeName {
		pubKeyToPeerConfig[peer.pubKey] = peer
	}

	dev, err := a.wgClient.Device(types.IfaceName)
	if err != nil {
		return fmt.Errorf("failed to obtain WireGuard device: %w", err)
	}

	for _, p := range dev.Peers {
		if pc, ok := pubKeyToPeerConfig[p.PublicKey]; ok {
			for _, ip := range p.AllowedIPs {
				if !pc.hasAllowedIP(ip) {
					pc.queueAllowedIPsRemove(ip)
				}
			}
			a.logger.Info(
				"Removing obsolete AllowedIPs from WireGuard peer",
				logfields.Endpoint, pc.endpoint,
				logfields.PubKey, pc.pubKey,
			)
			if err := a.updatePeerByConfig(pc); err != nil {
				a.logger.Error("Failed to remove stale AllowedIPs from WireGuard peer",
					logfields.Error, err,
					logfields.Endpoint, pc.endpoint,
				)
				return err
			}
		} else {
			a.logger.Info("Removing obsolete peer", logfields.PubKey, pc.pubKey)
			if err := a.deletePeerByPubKey(p.PublicKey); err != nil {
				return err
			}
		}
	}

	a.logger.Debug("Finished restore")

	return nil
}

func (a *Agent) UpdatePeer(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error {
	// To avoid running into a deadlock, we need to lock the IPCache before
	// calling a.Lock(), because IPCache might try to call into
	// OnIPIdentityCacheChange concurrently
	if a.needIPCacheEvents {
		a.ipCache.RLock()
		defer a.ipCache.RUnlock()
	}

	a.Lock()
	defer a.Unlock()

	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

	if pubKey == wgDummyPeerKey {
		return fmt.Errorf("node %q is not allowed to use the dummy peer key", nodeName)
	}

	if prevNodeName, ok := a.nodeNameByPubKey[pubKey]; ok {
		if nodeName != prevNodeName {
			return fmt.Errorf("detected duplicate public key. "+
				"node %q uses same key as existing node %q", nodeName, prevNodeName)
		}
	}

	peer := a.peerByNodeName[nodeName]

	// Reinitialize peer if its public key changed.
	if peer != nil && peer.pubKey != pubKey {
		a.logger.Debug(
			"Pubkey has changed",
			logfields.NodeName, nodeName,
		)
		if err := a.deletePeerByPubKey(peer.pubKey); err != nil {
			return err
		}
		peer = nil
	}

	// Initialize peer if this is the first time we are processing this node.
	if peer == nil {
		peer = &peerConfig{}

		if a.needIPCacheEvents {
			peer.queueAllowedIPsInsert(a.ipCache.LookupByHostRLocked(nodeIPv4, nodeIPv6)...)
		}
	}

	// Handle Node IP change
	if peer.nodeIPv4 != nil && !peer.nodeIPv4.Equal(nodeIPv4) {
		delete(a.nodeNameByNodeIP, peer.nodeIPv4.String())
		peer.queueAllowedIPsRemove(net.IPNet{
			IP:   peer.nodeIPv4,
			Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8),
		})
	}
	if peer.nodeIPv6 != nil && !peer.nodeIPv6.Equal(nodeIPv6) {
		delete(a.nodeNameByNodeIP, peer.nodeIPv6.String())
		peer.queueAllowedIPsRemove(net.IPNet{
			IP:   peer.nodeIPv6,
			Mask: net.CIDRMask(net.IPv6len*8, net.IPv6len*8),
		})
	}

	if option.Config.EnableIPv4 && nodeIPv4 != nil {
		ipn := net.IPNet{
			IP:   nodeIPv4,
			Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8),
		}
		if !peer.hasAllowedIP(ipn) {
			peer.queueAllowedIPsInsert(ipn)
		}
	}
	if option.Config.EnableIPv6 && nodeIPv6 != nil {
		ipn := net.IPNet{
			IP:   nodeIPv6,
			Mask: net.CIDRMask(net.IPv6len*8, net.IPv6len*8),
		}
		if !peer.hasAllowedIP(ipn) {
			peer.queueAllowedIPsInsert(ipn)
		}
	}

	ep := ""
	if option.Config.EnableIPv4 && nodeIPv4 != nil {
		ep = net.JoinHostPort(nodeIPv4.String(), strconv.Itoa(types.ListenPort))
	} else if option.Config.EnableIPv6 && nodeIPv6 != nil {
		ep = net.JoinHostPort(nodeIPv6.String(), strconv.Itoa(types.ListenPort))
	} else {
		return fmt.Errorf("missing node IP for node %q", nodeName)
	}

	epAddr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return fmt.Errorf("failed to resolve peer endpoint address: %w", err)
	}

	peer.pubKey = pubKey
	peer.endpoint = epAddr
	peer.nodeIPv4 = nodeIPv4
	peer.nodeIPv6 = nodeIPv6

	a.logger.Debug(
		"Updating peer",
		logfields.NodeName, nodeName,
		logfields.PubKey, pubKeyHex,
		logfields.NodeIPv4, nodeIPv4,
		logfields.NodeIPv6, nodeIPv6,
	)

	if err := a.updatePeerByConfig(peer); err != nil {
		return err
	}

	a.peerByNodeName[nodeName] = peer
	a.nodeNameByPubKey[pubKey] = nodeName
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
	delete(a.nodeNameByPubKey, peer.pubKey)

	if peer.nodeIPv4 != nil {
		delete(a.nodeNameByNodeIP, peer.nodeIPv4.String())
	}
	if peer.nodeIPv6 != nil {
		delete(a.nodeNameByNodeIP, peer.nodeIPv6.String())
	}

	return nil
}

func (a *Agent) deletePeerByPubKey(pubKey wgtypes.Key) error {
	a.logger.Debug(
		"Removing peer",
		logfields.PubKey, pubKey,
	)

	peerCfg := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	cfg := &wgtypes.Config{
		PrivateKey:   nil,
		ListenPort:   nil,
		FirewallMark: nil,
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peerCfg},
	}
	if err := a.wgClient.ConfigureDevice(types.IfaceName, *cfg); err != nil {
		return err
	}

	return nil
}

// updatePeerByConfig updates the WireGuard kernel peer config based on peerConfig p
func (a *Agent) updatePeerByConfig(p *peerConfig) error {
	addedIPs, removedIPs := p.queuedAllowedIPUpdates()
	peer := wgtypes.PeerConfig{
		PublicKey:  p.pubKey,
		Endpoint:   p.endpoint,
		AllowedIPs: addedIPs,
	}
	if option.Config.WireguardPersistentKeepalive != 0 {
		peer.PersistentKeepaliveInterval = &option.Config.WireguardPersistentKeepalive
	}
	cfg := wgtypes.Config{
		PrivateKey:   nil,
		ListenPort:   nil,
		FirewallMark: nil,
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peer},
	}

	// ConfigureDevice is called to add new allowedIPs:
	// 1. during the first call to UpdatePeer;
	// 2. when there are changes to the node's public key or IPs;
	// 3. on IPcache upsertions.
	if len(addedIPs) > 0 {
		a.logger.Debug(
			"Updating peer config",
			logfields.Endpoint, p.endpoint,
			logfields.PubKey, p.pubKey,
			logfields.IPAddrs, peer.AllowedIPs,
		)

		if err := a.wgClient.ConfigureDevice(types.IfaceName, cfg); err != nil {
			return fmt.Errorf("while adding IPs to peer: %w", err)
		}
	}

	// WireGuard's netlink API does not support direct removal of allowed IPs
	// from a peer. Instead you must use the WGPEER_F_REPLACE_ALLOWEDIPS flag
	// (set through the Go API with ReplaceAllowedIPs) to completely remove
	// all IPs from a peer and rebuild the allowed IPs list from scratch. This
	// removal and subsequent addition of IPs is non-atomic, meaning packets
	// sent to allowed IPs may be dropped during device updates as the transmit
	// path fails to look up the peer associated with an IP during this window.
	// This is most evident for UDP sockets, with calls to send and sendto
	// returning EHOSTUNREACH. Luckily, the API enables one peer to "steal" an
	// IP from another by simply assigning the allowed IP to another peer. We
	// exploit this property here to first move IPs we want to remove to a
	// "dummy peer" and then drain all the IPs from that peer using
	// WGPEER_F_REPLACE_ALLOWEDIPS. This hack is necessary to avoid disrupting
	// traffic when allowed IPs must be removed.
	if len(removedIPs) > 0 {
		cfg.Peers = []wgtypes.PeerConfig{
			{
				PublicKey:  wgDummyPeerKey,
				AllowedIPs: removedIPs,
			},
		}

		a.logger.Debug(
			"Moving removed IPs to dummy peer",
			logfields.Endpoint, p.endpoint,
			logfields.PubKey, wgDummyPeerKey,
			logfields.IPAddrs, removedIPs,
		)

		if err := a.wgClient.ConfigureDevice(types.IfaceName, cfg); err != nil {
			return fmt.Errorf("while moving removed IPs to dummy peer: %w", err)
		}

		a.logger.Debug(
			"Deleting dummy peer",
			logfields.PubKey, wgDummyPeerKey,
			logfields.IPAddrs, removedIPs,
		)

		if err := a.deletePeerByPubKey(wgDummyPeerKey); err != nil {
			return fmt.Errorf("while deleting dummy peer: %w", err)
		}
	}

	p.finishAllowedIPSync(addedIPs)
	p.finishAllowedIPSync(removedIPs)

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

// OnIPIdentityCacheChange implements ipcache.IPIdentityMappingListener
func (a *Agent) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
	_ *ipcache.Identity, _ ipcache.Identity, _ uint8, _ *ipcache.K8sMetadata, _ uint8) {
	ipnet := cidrCluster.AsIPNet()

	// This function is invoked from the IPCache with the
	// ipcache.IPIdentityCache lock held. We therefore need to be careful when
	// calling into ipcache.IPIdentityCache from Agent to avoid potential
	// deadlocks.
	a.Lock()
	defer a.Unlock()

	// We are only interested in IPCache entries where the hostIP is set, i.e.
	// updates with oldHostIP set for deleted entries and newHostIP set
	// for newly created entries.
	// A special case (i.e. an entry without a hostIP) is the remote node entry
	// itself when node-to-node encryption is enabled. We handle that case in
	// UpdatePeer(), i.e. we add any required remote node IPs to AllowedIPs
	// there.
	// If we do not find a WireGuard peer for a given hostIP, we intentionally
	// ignore the IPCache upserts here. We instead assume that UpdatePeer() will
	// eventually be called once a node starts participating in WireGuard
	// (or if its host IP changed). UpdatePeer initializes the allowedIPs
	// of newly discovered hostIPs by querying the IPCache, which will contain
	// all updates we might have skipped here before the hostIP was known.
	//
	// Note that we also ignore encryptKey here - it is only used by the
	// datapath. We only ever add AllowedIPs based on IPCache updates for nodes
	// which for which we already know the public key. If a node opts out of
	// encryption, it will not announce it's public key and thus will not be
	// part of the nodeNameByNodeIP map.
	var updatedPeer *peerConfig
	switch {
	case modType == ipcache.Delete && oldHostIP != nil:
		if nodeName, ok := a.nodeNameByNodeIP[oldHostIP.String()]; ok {
			if peer := a.peerByNodeName[nodeName]; peer != nil {
				if peer.hasAllowedIP(ipnet) {
					peer.queueAllowedIPsRemove(ipnet)
					updatedPeer = peer
				}
			}
		}
	case modType == ipcache.Upsert && newHostIP != nil:
		if nodeName, ok := a.nodeNameByNodeIP[newHostIP.String()]; ok {
			if peer := a.peerByNodeName[nodeName]; peer != nil {
				if !peer.hasAllowedIP(ipnet) {
					peer.queueAllowedIPsInsert(ipnet)
					updatedPeer = peer
				}
			}
		}
	}

	if updatedPeer != nil {
		if err := a.updatePeerByConfig(updatedPeer); err != nil {
			a.logger.Error(
				"Failed to update WireGuard peer after ipcache update",
				logfields.Error, err,
				logfields.Modification, modType,
				logfields.IPAddr, ipnet,
				logfields.OldNode, oldHostIP,
				logfields.NewNode, newHostIP,
				logfields.PubKey, updatedPeer.pubKey,
			)
		}
	}
}

// Status returns the state of the WireGuard tunnel managed by this instance.
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
				TransferTx:        p.TransmitBytes,
				TransferRx:        p.ReceiveBytes,
			}
			peers = append(peers, peer)
		}
	}

	var nodeEncryptionStatus = "Disabled"
	if option.Config.EncryptNode {
		if a.optOut {
			nodeEncryptionStatus = "OptedOut"
		} else {
			nodeEncryptionStatus = "Enabled"
		}
	}

	status := &models.WireguardStatus{
		NodeEncryption: nodeEncryptionStatus,
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

// peerConfig represents the kernel state of each WireGuard peer.
// In order to be able to add and remove individual IPs from the
// `AllowedIPs` list, we store a `peerConfig` for each known WireGuard peer.
// When a peer is first discovered via node manager, we obtain the remote
// peers `AllowedIPs` by querying Cilium's user-space copy of the IPCache
// in the agent. In addition, we also subscribe to IPCache updates in the
// WireGuard agent and update the `AllowedIPs` list of known peers
// accordingly.
type peerConfig struct {
	pubKey             wgtypes.Key
	endpoint           *net.UDPAddr
	nodeIPv4, nodeIPv6 net.IP
	allowedIPs         map[netip.Prefix]net.IPNet
	needsInsert        map[netip.Prefix]net.IPNet
	needsRemove        map[netip.Prefix]net.IPNet
}

func (p *peerConfig) lazyInitMaps() {
	if p.allowedIPs == nil {
		p.allowedIPs = map[netip.Prefix]net.IPNet{}
	}

	if p.needsInsert == nil {
		p.needsInsert = map[netip.Prefix]net.IPNet{}
	}

	if p.needsRemove == nil {
		p.needsRemove = map[netip.Prefix]net.IPNet{}
	}
}

// queueAllowedIPsInsert adds ip to the list of IPs that need to be inserted
// during the next update to this peer. The update is queued regardless of the
// current state of p.allowedIPs, so callers should use hasAllowedIP to
// avoid unnecessary updates.
func (p *peerConfig) queueAllowedIPsInsert(ips ...net.IPNet) {
	p.lazyInitMaps()

	for _, ip := range ips {
		pfx := ipnetToPrefix(ip)
		p.needsInsert[pfx] = ip
		delete(p.needsRemove, pfx)
	}
}

// queueAllowedIPsRemove adds ip to the list of IPs that need to be removed
// during the next update to this peer. The update is queued regardless of the
// current state of p.allowedIPs, so callers should use hasAllowedIP to
// avoid unnecessary updates.
func (p *peerConfig) queueAllowedIPsRemove(ips ...net.IPNet) {
	p.lazyInitMaps()

	for _, ip := range ips {
		pfx := ipnetToPrefix(ip)
		p.needsRemove[pfx] = ip
		delete(p.needsInsert, pfx)
	}
}

// queuedAllowedIPUpdates returns the set of allowed IP insertions and removals
// that are currently pending. If enableAllowedIPRemovals has not yet been
// called, this method will not return any removals.
func (p *peerConfig) queuedAllowedIPUpdates() (insert []net.IPNet, remove []net.IPNet) {
	for _, ip := range p.needsInsert {
		insert = append(insert, ip)
	}

	for _, ip := range p.needsRemove {
		remove = append(remove, ip)
	}

	return
}

// hasAllowedIP returns true if ip has been synced to this peer on the device.
func (p *peerConfig) hasAllowedIP(ip net.IPNet) bool {
	_, exists := p.allowedIPs[ipnetToPrefix(ip)]

	return exists
}

// finishAllowedIPSync signals that any queued updates for the given ips have
// been processed and synced to the device. This removes these ips from the
// update queues.
func (p *peerConfig) finishAllowedIPSync(ips []net.IPNet) {
	for _, ip := range ips {
		pfx := ipnetToPrefix(ip)
		if aip, exists := p.needsInsert[pfx]; exists {
			p.allowedIPs[pfx] = aip
			delete(p.needsInsert, pfx)
		}

		if _, exists := p.needsRemove[pfx]; exists {
			delete(p.allowedIPs, pfx)
			delete(p.needsRemove, pfx)
		}
	}

	if len(p.needsInsert) == 0 {
		p.needsInsert = nil
	}

	if len(p.needsRemove) == 0 {
		p.needsRemove = nil
	}
}

func ipnetToPrefix(ipn net.IPNet) netip.Prefix {
	cidr, _ := ipn.Mask.Size()
	return netip.PrefixFrom(netipx.MustFromStdIP(ipn.IP), cidr)
}
