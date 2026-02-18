// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package ipsec

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/prometheus/procfs"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/common/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/fswatcher"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	fakeencryptmap "github.com/cilium/cilium/pkg/maps/encrypt/fake"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

const (
	IPSecDirIn types.IPSecDir = 1 << iota
	IPSecDirOut
	IPSecDirFwd

	// Constants used to decode the IPsec secret in both formats:
	// 1. [spi] aead-algo aead-key icv-len
	// 2. [spi] auth-algo auth-key enc-algo enc-key [IP]
	offsetSPI      = 0
	offsetAeadAlgo = 1
	offsetAeadKey  = 2
	offsetICV      = 3
	offsetAuthAlgo = 1
	offsetAuthKey  = 2
	offsetEncAlgo  = 3
	offsetEncKey   = 4
	maxOffset      = offsetEncKey

	defaultDropPriority      = 100
	oldXFRMOutPolicyPriority = 50

	// The request ID which signifies all Cilium managed policies and states.
	AllReqID = 0

	// DefaultReqID is the default reqid used for all IPSec rules.
	DefaultReqID = ipsec.DefaultReqID
)

type dir string

const (
	dirUnspec  dir = "unspecified"
	dirIngress dir = "ingress"
	dirEgress  dir = "egress"
)

type ipSecKey struct {
	Spi    uint8
	KeyLen int
	ReqID  int
	Auth   *netlink.XfrmStateAlgo
	Crypt  *netlink.XfrmStateAlgo
	Aead   *netlink.XfrmStateAlgo
}

type oldXfrmStateKey struct {
	Spi int
	Dst [16]byte
}

var (
	wildcardIPv6   = net.ParseIP("0::0")
	wildcardCIDRv6 = &net.IPNet{
		IP:   wildcardIPv6,
		Mask: net.CIDRMask(0, 128),
	}
	wildcardIPv4   = net.ParseIP("0.0.0.0")
	wildcardCIDRv4 = &net.IPNet{
		IP:   wildcardIPv4,
		Mask: net.IPv4Mask(0, 0, 0, 0),
	}

	defaultDropMark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkEncrypt,
		Mask:  linux_defaults.IPsecMarkBitMask,
	}
	defaultDropPolicyIPv4 = &netlink.XfrmPolicy{
		Dir:      netlink.XFRM_DIR_OUT,
		Src:      wildcardCIDRv4,
		Dst:      wildcardCIDRv4,
		Mark:     defaultDropMark,
		Action:   netlink.XFRM_POLICY_BLOCK,
		Priority: defaultDropPriority,
	}
	defaultDropPolicyIPv6 = &netlink.XfrmPolicy{
		Dir:      netlink.XFRM_DIR_OUT,
		Src:      wildcardCIDRv6,
		Dst:      wildcardCIDRv6,
		Mark:     defaultDropMark,
		Action:   netlink.XFRM_POLICY_BLOCK,
		Priority: defaultDropPriority,
	}

	oldXFRMInMark *netlink.XfrmMark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkDecrypt,
		Mask:  linux_defaults.IPsecMarkBitMask,
	}
)

// Upon starting, the agent will load the ipsec key, set the SPI accordingly,
// and update the EncryptionKey in the local node object to the SPI.
type Agent struct {
	ipSecLock lock.RWMutex

	// These are provided in [newAgent].
	log        *slog.Logger
	localNode  *node.LocalNodeStore
	jobs       job.Group
	config     Config
	encryptMap encrypt.EncryptMap

	// These are initialized in [newAgent].
	authKeySize int
	spi         uint8
	// ipSecKeysGlobal is a map of all global IPsec keys per IP, plus a key for
	// the empty string which is used for the global key.
	ipSecKeysGlobal map[string]*ipSecKey
	// ipSecCurrentKeySPI is the SPI of the IPSec currently in use
	ipSecCurrentKeySPI uint8
	// ipSecKeysRemovalTime is used to track at which time a given key is
	// replaced with a newer one, allowing to reclaim old keys only after
	// enough time has passed since their replacement
	ipSecKeysRemovalTime map[uint8]time.Time
	// xfrmStateCache is a cache of XFRM states to avoid querying each time.
	// This is especially important for backgroundSync that is used to validate
	// if the XFRM state is correct, without usually modyfing anything.
	// The cache is invalidated whenever a new XFRM state is added/updated/removed,
	// but also in case of TTL expiration.
	// It provides XfrmStateAdd/Update/Del wrappers that ensure cache
	// is correctly invalidate.
	xfrmStateCache *xfrmStateListCache
}

// newAgent creates a new IPSec agent.
func newAgent(lc cell.Lifecycle, log *slog.Logger, jg job.Group, lns *node.LocalNodeStore, c Config, em encrypt.EncryptMap) *Agent {
	ipsec := &Agent{
		log:        log,
		localNode:  lns,
		jobs:       jg,
		config:     c,
		encryptMap: em,

		authKeySize:          0,
		spi:                  0,
		ipSecKeysGlobal:      map[string]*ipSecKey{},
		ipSecKeysRemovalTime: map[uint8]time.Time{},
		xfrmStateCache:       NewXfrmStateListCache(time.Minute, c.EnableIPsecXfrmStateCaching),
	}
	lc.Append(ipsec)
	return ipsec
}

func (a *Agent) Start(cell.HookContext) error {
	if !a.config.EncryptNode {
		a.deleteIPsecEncryptRoute()
	}
	if !a.Enabled() {
		return nil
	}

	var err error
	a.authKeySize, a.spi, err = a.loadIPSecKeysFile(a.config.IPsecKeyFile)
	if err != nil {
		return err
	}
	if err := a.setIPSecSPI(a.spi); err != nil {
		return err
	}

	a.localNode.Update(func(n *node.LocalNode) {
		n.EncryptionKey = a.spi
	})

	return nil
}

// StartBackgroundJobs starts the keyfile watcher and stale key reclaimer jobs.
func (a *Agent) StartBackgroundJobs(handler types.NodeHandler) error {
	if !a.Enabled() {
		return nil
	}
	if err := a.startKeyfileWatcher(handler); err != nil {
		return fmt.Errorf("failed to start IPsec keyfile watcher: %w", err)
	}
	a.jobs.Add(job.Timer("stale-key-reclaimer", a.onTimer, time.Minute))
	return nil
}

func (a *Agent) Stop(cell.HookContext) error {
	return nil
}

func (a *Agent) AuthKeySize() int {
	return a.authKeySize
}

func (a *Agent) SPI() uint8 {
	return a.spi
}

func (a *Agent) Enabled() bool {
	return a.config.Enabled()
}

func (a *Agent) getGlobalIPsecKey(ip net.IP) *ipSecKey {
	a.ipSecLock.RLock()
	defer a.ipSecLock.RUnlock()

	key, scoped := a.ipSecKeysGlobal[ip.String()]
	if !scoped {
		key = a.ipSecKeysGlobal[""]
	}
	return key
}

// computeNodeIPsecKey computes per-node-pair IPsec keys from the global,
// pre-shared key. The per-node-pair keys are computed with a SHA256 hash of
// the global key, source node IP, destination node IP appended together.
func computeNodeIPsecKey(globalKey, srcNodeIP, dstNodeIP, srcBootID, dstBootID []byte) []byte {
	inputLen := len(globalKey) + len(srcNodeIP) + len(dstNodeIP) + len(srcBootID) + len(dstBootID)
	input := make([]byte, 0, inputLen)
	input = append(input, globalKey...)
	input = append(input, srcNodeIP...)
	input = append(input, dstNodeIP...)
	input = append(input, srcBootID[:36]...)
	input = append(input, dstBootID[:36]...)

	var hash []byte
	if len(globalKey) <= 32 {
		h := sha256.Sum256(input)
		hash = h[:]
	} else {
		h := sha512.Sum512(input)
		hash = h[:]
	}
	return hash[:len(globalKey)]
}

// canonicalIP returns a canonical IPv4 address (4 bytes)
// in case we were dealing with a v4 mapped V6 address.
func canonicalIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// deriveNodeIPsecKey builds a per-node-pair ipSecKey object from the global
// ipSecKey object.
func deriveNodeIPsecKey(globalKey *ipSecKey, srcNodeIP, dstNodeIP net.IP, srcBootID, dstBootID []byte) *ipSecKey {
	nodeKey := &ipSecKey{
		Spi:   globalKey.Spi,
		ReqID: globalKey.ReqID,
	}

	srcNodeIP = canonicalIP(srcNodeIP)
	dstNodeIP = canonicalIP(dstNodeIP)

	if globalKey.Aead != nil {
		nodeKey.Aead = &netlink.XfrmStateAlgo{
			Name:   globalKey.Aead.Name,
			Key:    computeNodeIPsecKey(globalKey.Aead.Key, srcNodeIP, dstNodeIP, srcBootID, dstBootID),
			ICVLen: globalKey.Aead.ICVLen,
		}
	} else {
		nodeKey.Auth = &netlink.XfrmStateAlgo{
			Name: globalKey.Auth.Name,
			Key:  computeNodeIPsecKey(globalKey.Auth.Key, srcNodeIP, dstNodeIP, srcBootID, dstBootID),
		}

		nodeKey.Crypt = &netlink.XfrmStateAlgo{
			Name: globalKey.Crypt.Name,
			Key:  computeNodeIPsecKey(globalKey.Crypt.Key, srcNodeIP, dstNodeIP, srcBootID, dstBootID),
		}
	}

	return nodeKey
}

// We want one IPsec key per node pair. For a pair of nodes A and B with IP
// addresses a and b, and boot ids x and y respectively, we will therefore
// install two different keys:
// Node A                   <> Node B
// XFRM IN:  key(b+a+y+x)      XFRM IN:  key(a+b+x+y)
// XFRM OUT: key(a+b+x+y)      XFRM OUT: key(b+a+y+x)
// This is done such that, for each pair of nodes A, B, the key used for
// decryption on A (XFRM IN) is the same key used for encryption on B (XFRM
// OUT), and vice versa. And its key automatically resets on each node reboot.
func (a *Agent) getNodeIPsecKey(localNodeIP, remoteNodeIP net.IP, srcBootID, dstBootID string) (*ipSecKey, error) {
	globalKey := a.getGlobalIPsecKey(localNodeIP)
	if globalKey == nil {
		return nil, fmt.Errorf("global IPsec key missing")
	}

	srcBootIDBytes := []byte(srcBootID)
	dstBootIDBytes := []byte(dstBootID)
	if len(srcBootIDBytes) < 36 || len(dstBootIDBytes) < 36 {
		return nil, fmt.Errorf("incorrect size for boot ID, should be at least 36 characters long")
	}

	return deriveNodeIPsecKey(globalKey, localNodeIP, remoteNodeIP, srcBootIDBytes, dstBootIDBytes), nil
}

func ipSecNewState(keys *ipSecKey) *netlink.XfrmState {
	state := netlink.XfrmState{
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Proto:        netlink.XFRM_PROTO_ESP,
		ESN:          true,
		Spi:          int(keys.Spi),
		Reqid:        keys.ReqID,
		ReplayWindow: 1024,
	}
	if keys.Aead != nil {
		state.Aead = keys.Aead
	} else {
		state.Crypt = keys.Crypt
		state.Auth = keys.Auth
	}
	return &state
}

func ipSecNewPolicy() *netlink.XfrmPolicy {
	policy := netlink.XfrmPolicy{}
	return &policy
}

func ipSecAttachPolicyTempl(policy *netlink.XfrmPolicy, keys *ipSecKey, srcIP, dstIP net.IP, spi bool, optional bool) {
	tmpl := netlink.XfrmPolicyTmpl{
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Dst:   dstIP,
		Src:   srcIP,
		Reqid: keys.ReqID,
	}

	if optional {
		tmpl.Optional = 1
		// If the template is optional, we might as well make it accept
		// everything it can.
		tmpl.Reqid = 0
		tmpl.Src = nil
		tmpl.Dst = nil
		spi = false
	}

	if spi {
		tmpl.Spi = int(keys.Spi)
	}

	policy.Tmpls = append(policy.Tmpls, tmpl)
}

// xfrmStateReplace attempts to add a new XFRM state only if one doesn't
// already exist. If it doesn't but some other XFRM state conflicts, then
// we attempt to remove the conflicting state before trying to add again.
func (a *Agent) xfrmStateReplace(new *netlink.XfrmState, remoteRebooted bool) error {
	states, err := a.xfrmStateCache.XfrmStateList()
	if err != nil {
		return fmt.Errorf("Cannot get XFRM state: %w", err)
	}

	scopedLog := a.log.With(
		logfields.SPI, new.Spi,
		logfields.SourceIP, new.Src,
		logfields.DestinationIP, new.Dst,
		logfields.TrafficDirection, getDirFromXfrmMark(new.Mark),
		logfields.NodeID, getNodeIDAsHexFromXfrmMark(new.Mark),
	)

	// Check if the XFRM state already exists
	for _, s := range states {
		if xfrmIPEqual(s.Src, new.Src) && xfrmIPEqual(s.Dst, new.Dst) &&
			xfrmMarkEqual(s.Mark, new.Mark) && xfrmMarkEqual(s.OutputMark, new.OutputMark) &&
			s.Spi == new.Spi {
			if remoteRebooted {
				// This should happen only when a node reboots.
				// We can safely perform a non-atomic swap of the XFRM state
				// for both the IN and OUT directions because:
				// - For the IN direction, we can't leak anything. At most
				//   we'll drop a few encrypted packets while updating.
				// - For the OUT direction, we also can't leak anything due to
				//   having an existing XFRM policy which will match and drop
				//   packets if the state is missing. At most we will drop a
				//   few encrypted packets while updating.
				scopedLog.Info("Non-atomically updating IPsec XFRM state due to remote boot ID change")
				a.xfrmStateCache.XfrmStateDel(&s)
				break
			}
			return nil
		}
	}

	// It doesn't exist so let's attempt to add it.
	firstAttemptErr := a.xfrmStateCache.XfrmStateAdd(new)
	if !os.IsExist(firstAttemptErr) {
		return firstAttemptErr
	}
	scopedLog.Error("Failed to add XFRM state due to conflicting state")

	// An existing state conflicts with this one. We need to remove the
	// existing one first.
	deletedSomething, err := a.xfrmDeleteConflictingState(states, new)
	if err != nil {
		return err
	}

	// If no conflicting state was found and deleted, there's no point in
	// attempting to add again.
	if !deletedSomething {
		return firstAttemptErr
	}
	return a.xfrmStateCache.XfrmStateAdd(new)
}

// Temporarily remove an XFRM state to allow the addition of another,
// conflicting XFRM state. This function removes the conflicting state and
// prepares a defer callback to re-add it with proper logging.
func (a *Agent) xfrmTemporarilyRemoveState(scopedLog *slog.Logger, state netlink.XfrmState, dir string) (error, func()) {
	stats, err := procfs.NewXfrmStat()
	errorCnt := 0
	if err != nil {
		scopedLog.Error("Error while getting XFRM stats before state removal", logfields.Error, err)
	} else {
		if dir == "IN" {
			errorCnt = stats.XfrmInNoStates
		} else {
			errorCnt = stats.XfrmOutNoStates
		}
	}

	start := time.Now()
	if err := a.xfrmStateCache.XfrmStateDel(&state); err != nil {
		return err, nil
	}
	return nil, func() {
		if err := a.xfrmStateCache.XfrmStateAdd(&state); err != nil {
			scopedLog.Error("Failed to re-add old XFRM state",
				logfields.Directory, dir,
				logfields.Error, err,
			)
		}
		elapsed := time.Since(start)

		stats, err := procfs.NewXfrmStat()
		if err != nil {
			scopedLog.Error("Error while getting XFRM stats after state removal", logfields.Error, err)
			errorCnt = 0
		} else {
			if dir == "IN" {
				errorCnt = stats.XfrmInNoStates - errorCnt
			} else {
				errorCnt = stats.XfrmOutNoStates - errorCnt
			}
		}
		scopedLog.Info("Temporarily removed old XFRM state",
			logfields.Directory, dir,
			logfields.PacketsDropped, errorCnt,
			logfields.Duration, elapsed,
		)
	}
}

// Attempt to remove any XFRM state that conflicts with the state we just tried
// to add. To find those conflicting states, we need to use the same logic that
// the kernel used to reject our check with EEXIST. That logic is upstream in
// __xfrm_state_lookup.
func (a *Agent) xfrmDeleteConflictingState(states []netlink.XfrmState, new *netlink.XfrmState) (bool, error) {
	var (
		deletedSomething bool
		errs             = resiliency.NewErrorSet("failed to delete conflicting XFRM states", len(states))
	)
	for _, s := range states {
		if new.Spi == s.Spi && (new.Mark == nil) == (s.Mark == nil) &&
			(new.Mark == nil || new.Mark.Value&new.Mark.Mask&s.Mark.Mask == s.Mark.Value) &&
			xfrmIPEqual(new.Dst, s.Dst) {
			if err := a.xfrmStateCache.XfrmStateDel(&s); err != nil {
				errs.Add(err)
				continue
			}
			deletedSomething = true
			a.log.Info("Removed a conflicting XFRM state",
				logfields.SPI, s.Spi,
				logfields.SourceIP, s.Src,
				logfields.DestinationIP, s.Dst,
				logfields.TrafficDirection, getDirFromXfrmMark(s.Mark),
				logfields.NodeID, getNodeIDAsHexFromXfrmMark(s.Mark),
			)
		}
	}
	return deletedSomething, errs.Error()
}

// This function compares two IP addresses and returns true if they are equal.
// This is unfortunately necessary because our netlink library returns nil IPv6
// addresses as nil IPv4 addresses and net.IP.Equal rightfully considers those
// are different.
func xfrmIPEqual(ip1, ip2 net.IP) bool {
	if ip1.IsUnspecified() && ip2.IsUnspecified() {
		return true
	}
	return ip1.Equal(ip2)
}

// Returns true if two XFRM marks are identical. They should be either both nil
// or have the same mark value and mask.
func xfrmMarkEqual(mark1, mark2 *netlink.XfrmMark) bool {
	if (mark1 == nil) != (mark2 == nil) {
		return false
	}
	return mark1 == nil || (mark1.Value == mark2.Value && mark1.Mask == mark2.Mask)
}

func (a *Agent) ipSecReplaceStateIn(params *types.IPSecParameters) (uint8, error) {
	key, err := a.getNodeIPsecKey(*params.SourceTunnelIP, *params.DestTunnelIP, params.RemoteBootID, params.LocalBootID)
	if err != nil {
		return 0, err
	}
	key.ReqID = params.ReqID
	state := ipSecNewState(key)
	state.Src = *params.SourceTunnelIP
	state.Dst = *params.DestTunnelIP
	state.Mark = generateDecryptMark(linux_defaults.RouteMarkDecrypt, params.RemoteNodeID)
	if params.ZeroOutputMark {
		state.OutputMark = &netlink.XfrmMark{
			Value: 0,
			Mask:  linux_defaults.OutputMarkMask,
		}
	} else {
		state.OutputMark = &netlink.XfrmMark{
			Value: linux_defaults.RouteMarkDecrypt,
			Mask:  linux_defaults.OutputMarkMask,
		}
	}
	// We want to clear the node ID regardless of zeroMark parameter. That
	// value is never needed after decryption.
	state.OutputMark.Mask |= linux_defaults.IPsecMarkMaskNodeID

	return key.Spi, a.xfrmStateReplace(state, params.RemoteRebooted)
}

func (a *Agent) ipSecReplaceStateOut(params *types.IPSecParameters) (uint8, error) {
	key, err := a.getNodeIPsecKey(*params.SourceTunnelIP, *params.DestTunnelIP, params.LocalBootID, params.RemoteBootID)
	if err != nil {
		return 0, err
	}
	key.ReqID = params.ReqID
	state := ipSecNewState(key)
	state.Src = *params.SourceTunnelIP
	state.Dst = *params.DestTunnelIP
	state.Mark = generateEncryptMark(key.Spi, params.RemoteNodeID)
	state.OutputMark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkEncrypt,
		Mask:  linux_defaults.OutputMarkMask,
	}
	return key.Spi, a.xfrmStateReplace(state, params.RemoteRebooted)
}

func (a *Agent) ipSecReplacePolicyIn(params *types.IPSecParameters) error {
	// We can use the global IPsec key here because we are not going to
	// actually use the secret itself.
	key := a.getGlobalIPsecKey(params.DestSubnet.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}
	key.ReqID = params.ReqID

	policy := ipSecNewPolicy()
	policy.Src = params.SourceSubnet
	policy.Dst = params.DestSubnet
	policy.Dir = netlink.XFRM_DIR_IN
	ipSecAttachPolicyTempl(policy, key, *params.SourceTunnelIP, *params.DestTunnelIP, false, true)
	return netlink.XfrmPolicyUpdate(policy)
}

func (a *Agent) ipsecReplacePolicyFwd(params *types.IPSecParameters) error {
	// We can use the global IPsec key here because we are not going to
	// actually use the secret itself.
	key := a.getGlobalIPsecKey(net.IP{})
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}

	policy := ipSecNewPolicy()
	policy.Dir = netlink.XFRM_DIR_FWD
	key.ReqID = params.ReqID
	policy.Priority = linux_defaults.IPsecFwdPriority

	// In case of fwd policies, we should tell the kernel the tmpl src
	// doesn't matter; we want all fwd packets to go through.
	policy.Src = params.SourceSubnet
	policy.Dst = params.DestSubnet

	ipSecAttachPolicyTempl(policy, key, *params.SourceTunnelIP, *params.DestTunnelIP, false, true)
	return netlink.XfrmPolicyUpdate(policy)
}

// Installs a catch-all policy for outgoing traffic that has the encryption
// bit. The goal here is to catch any traffic that may passthrough our
// encryption while we are replacing XFRM policies & states. Those operations
// cannot always be performed atomically so we may have brief moments where
// there is no XFRM policy to encrypt a subset of traffic. This policy ensures
// we drop such traffic and don't let it flow in plain text.
//
// We do need to match on the mark because there is also traffic flowing
// through XFRM that we don't want to encrypt (e.g., hostns traffic).
func IPsecDefaultDropPolicy(ipv6 bool) error {
	defaultDropPolicy := defaultDropPolicyIPv4
	if ipv6 {
		defaultDropPolicy = defaultDropPolicyIPv6
	}

	err := netlink.XfrmPolicyUpdate(defaultDropPolicy)

	return err
}

// ipSecXfrmMarkSetSPI takes a XfrmMark base value, an SPI, returns the mark
// value with the SPI value encoded in it
func ipSecXfrmMarkSetSPI(markValue uint32, spi uint8) uint32 {
	return markValue | (uint32(spi) << linux_defaults.IPsecXFRMMarkSPIShift)
}

func getNodeIDAsHexFromXfrmMark(mark *netlink.XfrmMark) string {
	return fmt.Sprintf("0x%x", ipsec.GetNodeIDFromXfrmMark(mark))
}

func getDirFromXfrmMark(mark *netlink.XfrmMark) dir {
	if mark == nil {
		return dirUnspec
	}
	bitwiseResult := mark.Value & linux_defaults.RouteMarkMask
	switch bitwiseResult {
	case linux_defaults.RouteMarkDecrypt:
		return dirIngress
	case linux_defaults.RouteMarkEncrypt:
		return dirEgress
	}
	return dirUnspec
}

func generateEncryptMark(spi uint8, nodeID uint16) *netlink.XfrmMark {
	val := ipSecXfrmMarkSetSPI(linux_defaults.RouteMarkEncrypt, spi)
	val |= uint32(nodeID) << 16
	return &netlink.XfrmMark{
		Value: val,
		Mask:  linux_defaults.IPsecMarkMaskOut,
	}
}

func generateDecryptMark(decryptBit uint32, nodeID uint16) *netlink.XfrmMark {
	val := decryptBit | (uint32(nodeID) << 16)
	return &netlink.XfrmMark{
		Value: val,
		Mask:  linux_defaults.IPsecMarkMaskIn,
	}
}

func (a *Agent) ipSecReplacePolicyOut(params *types.IPSecParameters) error {
	// TODO: Remove old policy pointing to target net

	// We can use the global IPsec key here because we are not going to
	// actually use the secret itself.
	key := a.getGlobalIPsecKey(params.DestSubnet.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}
	key.ReqID = params.ReqID

	policy := ipSecNewPolicy()
	policy.Src = params.SourceSubnet
	policy.Dst = params.DestSubnet
	policy.Dir = netlink.XFRM_DIR_OUT
	policy.Mark = generateEncryptMark(key.Spi, params.RemoteNodeID)
	ipSecAttachPolicyTempl(policy, key, *params.SourceTunnelIP, *params.DestTunnelIP, true, false)
	return netlink.XfrmPolicyUpdate(policy)
}

// Returns true if the given mark matches on the node ID. This works because
// the node ID match is always in the first 16 bits.
func matchesOnNodeID(mark *netlink.XfrmMark) bool {
	return mark != nil &&
		mark.Mask&linux_defaults.IPsecMarkMaskNodeID == linux_defaults.IPsecMarkMaskNodeID
}

func matchesOnDst(a *net.IPNet, b *net.IPNet) bool {
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

func (a *Agent) ipsecDeleteXfrmState(nodeID uint16) error {
	xfrmStateList, err := a.xfrmStateCache.XfrmStateList()
	if err != nil {
		a.log.Warn("Failed to list XFRM states for deletion",
			logfields.NodeID, nodeID,
			logfields.Error, err)
		return err
	}

	xfrmStatesToDelete := []netlink.XfrmState{}
	oldXfrmInStates := map[oldXfrmStateKey]netlink.XfrmState{}
	for _, s := range xfrmStateList {
		if matchesOnNodeID(s.Mark) && ipsec.GetNodeIDFromXfrmMark(s.Mark) == nodeID {
			xfrmStatesToDelete = append(xfrmStatesToDelete, s)
		}
		if xfrmMarkEqual(s.Mark, oldXFRMInMark) {
			key := oldXfrmStateKey{
				Spi: s.Spi,
				Dst: [16]byte(s.Dst.To16()),
			}
			oldXfrmInStates[key] = s
		}
	}

	errs := resiliency.NewErrorSet(fmt.Sprintf("failed to delete node (%d) xfrm states", nodeID), len(xfrmStateList))
	for _, s := range xfrmStatesToDelete {
		key := oldXfrmStateKey{
			Spi: s.Spi,
			Dst: [16]byte(s.Dst.To16()),
		}
		var oldXfrmInState *netlink.XfrmState = nil
		old, ok := oldXfrmInStates[key]
		if ok {
			oldXfrmInState = &old
		}
		if err := a.safeDeleteXfrmState(&s, oldXfrmInState); err != nil {
			errs.Add(fmt.Errorf("failed to delete xfrm state (%s): %w", s.String(), err))
		}
	}

	return errs.Error()
}

// safeDeleteXfrmState deletes the given XFRM state. Specifically, if the
// state is to catch ingress traffic marked with nodeID (0xXXXX0d00), we
// temporarily remove the old XFRM state that matches 0xd00/0xf00. This is to
// workaround a kernel issue that prevents us from deleting a specific XFRM
// state (e.g. catching 0xXXXX0d00/0xffff0f00) when there is also a general
// xfrm state (e.g. catching 0xd00/0xf00). When both XFRM states coexist,
// kernel deletes the general XFRM state instead of the specific one, even if
// the deleting request is for the specific one.
func (a *Agent) safeDeleteXfrmState(state *netlink.XfrmState, oldState *netlink.XfrmState) (err error) {
	if getDirFromXfrmMark(state.Mark) == dirIngress && ipsec.GetNodeIDFromXfrmMark(state.Mark) != 0 && oldState != nil {

		errs := resiliency.NewErrorSet("failed to delete old xfrm states", 1)

		scopedLog := a.log.With(
			logfields.SPI, state.Spi,
			logfields.SourceIP, state.Src,
			logfields.DestinationIP, state.Dst,
			logfields.TrafficDirection, getDirFromXfrmMark(state.Mark),
			logfields.NodeID, getNodeIDAsHexFromXfrmMark(state.Mark),
		)

		err, deferFn := a.xfrmTemporarilyRemoveState(scopedLog, *oldState, string(dirIngress))
		if err != nil {
			errs.Add(fmt.Errorf("Failed to remove old XFRM %s state %s: %w", string(dirIngress), oldState.String(), err))
		} else {
			defer deferFn()
		}
		if err := errs.Error(); err != nil {
			scopedLog.Error("Failed to clean up old XFRM state", logfields.Error, err)
			return err
		}
	}

	return a.xfrmStateCache.XfrmStateDel(state)
}

func (a *Agent) ipsecDeleteXfrmPolicy(nodeID uint16) error {
	xfrmPolicyList, err := safenetlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		a.log.Warn("Failed to list XFRM policies for deletion",
			logfields.NodeID, nodeID,
			logfields.Error, err)
		return fmt.Errorf("failed to list xfrm policies: %w", err)
	}
	errs := resiliency.NewErrorSet("failed to delete xfrm policies", len(xfrmPolicyList))
	for _, p := range xfrmPolicyList {
		if matchesOnNodeID(p.Mark) && ipsec.GetNodeIDFromXfrmMark(p.Mark) == nodeID {
			if err := netlink.XfrmPolicyDel(&p); err != nil {
				errs.Add(fmt.Errorf("unable to delete xfrm policy %s: %w", p.String(), err))
			}
		}
	}
	if err := errs.Error(); err != nil {
		a.log.Warn("Failed to delete XFRM policy",
			logfields.NodeID, nodeID,
			logfields.Error, err)
		return err
	}

	return nil
}

/* UpsertIPsecEndpoint updates the IPSec context for a new endpoint inserted in
 * the ipcache. Currently we support a global crypt/auth keyset that will encrypt
 * all traffic between endpoints. An IPSec context consists of two pieces a policy
 * and a state, the security policy database (SPD) and security association
 * database (SAD). These are implemented using the Linux kernels XFRM implementation.
 *
 * For all traffic that matches a policy, the policy tuple used is
 * (sip/mask, dip/mask, dev) with an optional mark field used in the Cilium implementation
 * to ensure only expected traffic is encrypted. The state hashtable is searched for
 * a matching state associated with that flow. The Linux kernel will do a series of
 * hash lookups to find the most specific state (xfrm_dst) possible. The hash keys searched are
 * the following, (daddr, saddr, reqid, encap_family), (daddr, wildcard, reqid, encap),
 * (mark, daddr, spi, proto, encap). Any "hits" in the hash table will subsequently
 * have the SPI checked to ensure it also matches. Encap is ignored in our case here
 * and can be used with UDP encap if wanted.
 *
 * The implications of the (inflexible!) hash key implementation is that in-order
 * to have a policy/state match we _must_ insert a state for each daddr. For Cilium
 * this translates to a state entry per node. We learn the nodes/endpoints by
 * listening to ipcache events. Finally, because IPSec is unidirectional a state
 * is needed for both ingress and egress. Denoted by the DIR on the xfrm cmd line
 * in the policy lookup. In the Cilium case, where we have IPSec between all
 * endpoints this results in two policy rules per node, one for ingress
 * and one for egress.
 *
 * For a concrete example consider two cluster nodes using transparent mode e.g.
 * without an IPSec tunnel IP. Cluster Node A has host_ip 10.156.0.1 with an
 * endpoint assigned to IP 10.156.2.2 and cluster Node B has host_ip 10.182.0.1
 * with an endpoint using IP 10.182.3.3. Then on Node A there will be a two policy
 * entries and a set of State entries,
 *
 * Policy1(src=10.182.0.0/16,dst=10.156.0.1/16,dir=in,tmpl(spi=#spi,reqid=#reqid))
 * Policy2(src=10.156.0.0/16,dst=10.182.0.1/16,dir=out,tmpl(spi=#spi,reqid=#reqid))
 * State1(src=*,dst=10.182.0.1,spi=#spi,reqid=#reqid,...)
 * State2(src=*,dst=10.156.0.1,spi=#spi,reqid=#reqid,...)
 *
 * Design Note: For newer kernels a BPF xfrm interface would greatly simplify the
 * state space. Basic idea would be to reference a state using any key generated
 * from BPF program allowing for a single state per security ctx.
 */
func (a *Agent) UpsertIPsecEndpoint(params *types.IPSecParameters) (uint8, error) {
	var spi uint8
	var err error

	/* TODO: state reference ID is (dip,spi) which can be duplicated in the current global
	 * mode. The duplication is on _all_ ingress states because dst_ip == host_ip in this
	 * case and only a single spi entry is in use. Currently no check is done to avoid
	 * attempting to add duplicate (dip,spi) states and we get 'file exist' error. These
	 * errors are expected at the moment but perhaps it would be better to avoid calling
	 * netlink API at all when we "know" an entry is a duplicate. To do this the xfer
	 * state would need to be cached in the ipcache.
	 */
	if !params.SourceTunnelIP.Equal(*params.DestTunnelIP) {
		if params.Dir&IPSecDirIn != 0 {
			if spi, err = a.ipSecReplaceStateIn(params); err != nil {
				return 0, fmt.Errorf("unable to replace local state: %w", err)
			}
			if err = a.ipSecReplacePolicyIn(params); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy in: %w", err)
				}
			}
		}

		if params.Dir&IPSecDirFwd != 0 {
			if err = a.ipsecReplacePolicyFwd(params); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy fwd: %w", err)
				}
			}
		}

		if params.Dir&IPSecDirOut != 0 {
			if spi, err = a.ipSecReplaceStateOut(params); err != nil {
				return 0, fmt.Errorf("unable to replace remote state: %w", err)
			}

			if err = a.ipSecReplacePolicyOut(params); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy out: %w", err)
				}
			}
		}
	}
	return spi, nil
}

// DeleteIPsecEndpoint deletes a endpoint associated with the remote IP address
func (a *Agent) DeleteIPsecEndpoint(nodeID uint16) error {
	return errors.Join(a.ipsecDeleteXfrmState(nodeID), a.ipsecDeleteXfrmPolicy(nodeID))
}

func isXfrmPolicyCilium(policy netlink.XfrmPolicy) bool {
	if policy.Mark == nil {
		// Check if its our fwd rule, we don't have a mark
		// on this rule so use priority.
		if policy.Dir == netlink.XFRM_DIR_FWD &&
			policy.Priority == linux_defaults.IPsecFwdPriority {
			return true
		}
		// Check if its our catch-all IN policy.
		if policy.Dir == netlink.XFRM_DIR_IN && len(policy.Tmpls) == 1 {
			tmpl := policy.Tmpls[0]
			if tmpl.Spi == 0 && tmpl.Reqid == 0 && tmpl.Optional == 1 {
				return true
			}
		}
		return false
	}

	if (policy.Mark.Value & linux_defaults.RouteMarkDecrypt) != 0 {
		return true
	}
	if (policy.Mark.Value & linux_defaults.RouteMarkEncrypt) != 0 {
		return true
	}
	return false
}

func isXfrmStateCilium(state netlink.XfrmState) bool {
	if state.Mark == nil {
		return false
	}
	if (state.Mark.Value & linux_defaults.RouteMarkDecrypt) != 0 {
		return true
	}
	if (state.Mark.Value & linux_defaults.RouteMarkEncrypt) != 0 {
		return true
	}
	return false
}

// DeleteXFRM will remove XFRM policies and states by their XFRM request ID.
//
// AllReqID can be used for `reqID` to remove all Cilium managed XFRM policies
// and states.
func (a *Agent) DeleteXFRM(reqID int) error {
	xfrmPolicyList, err := safenetlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	ee := resiliency.NewErrorSet("failed to delete XFRM policies", len(xfrmPolicyList))
policy:
	for _, p := range xfrmPolicyList {
		if !isXfrmPolicyCilium(p) {
			continue
		}

		// check if there exists a template with req ID as the one we are looking for
		// if so, delete the policy.
		for _, tmpl := range p.Tmpls {
			if reqID == AllReqID || tmpl.Reqid == reqID {
				if err := netlink.XfrmPolicyDel(&p); err != nil {
					ee.Add(err)
				}
				continue policy
			}
		}
	}
	if err := ee.Error(); err != nil {
		return err
	}

	xfrmStateList, err := a.xfrmStateCache.XfrmStateList()
	if err != nil {
		a.log.Warn("unable to fetch xfrm state list", logfields.Error, err)
		return err
	}
	ee = resiliency.NewErrorSet("failed to delete XFRM states", len(xfrmStateList))
	for _, s := range xfrmStateList {
		if isXfrmStateCilium(s) && (reqID == AllReqID || s.Reqid == reqID) {
			if err := a.xfrmStateCache.XfrmStateDel(&s); err != nil {
				ee.Add(err)
			}
		}
	}

	return ee.Error()
}

// DeleteXfrmPolicyOut will remove XFRM OUT policies by their node ID and destination subnet.
func (a *Agent) DeleteXfrmPolicyOut(nodeID uint16, dst *net.IPNet) error {
	if dst.IP.To4() != nil {
		return a.deleteXfrmPolicyOutFamily(nodeID, dst, netlink.FAMILY_V4)
	} else {
		return a.deleteXfrmPolicyOutFamily(nodeID, dst, netlink.FAMILY_V6)
	}
}

func (a *Agent) deleteXfrmPolicyOutFamily(nodeID uint16, dst *net.IPNet, family int) error {
	xfrmPolicyList, err := safenetlink.XfrmPolicyList(family)
	if err != nil {
		a.log.Warn("Failed to list XFRM OUT policies for deletion", logfields.Error, err)
		return fmt.Errorf("failed to list xfrm out policies: %w", err)
	}
	errs := resiliency.NewErrorSet("failed to delete xfrm out policies", len(xfrmPolicyList))
	for _, p := range xfrmPolicyList {
		if !matchesOnNodeID(p.Mark) || ipsec.GetNodeIDFromXfrmMark(p.Mark) != nodeID || !matchesOnDst(p.Dst, dst) {
			continue
		}
		if err := netlink.XfrmPolicyDel(&p); err != nil {
			errs.Add(fmt.Errorf("unable to delete xfrm out policy %s: %w", p.String(), err))
		}
	}
	if err := errs.Error(); err != nil {
		a.log.Warn("Failed to delete XFRM OUT policy", logfields.Error, err)
		return err
	}

	return nil
}

func decodeIPSecKey(keyRaw string) (int, []byte, error) {
	// As we have released the v1.4.0 docs telling the users to write the
	// k8s secret with the prefix "0x" we have to remove it if it is present,
	// so we can decode the secret.
	if keyRaw == "\"\"" {
		return 0, nil, nil
	}
	keyTrimmed := strings.TrimPrefix(keyRaw, "0x")
	key, err := hex.DecodeString(keyTrimmed)
	return len(keyTrimmed), key, err
}

// loadIPSecKeysFile imports IPSec auth and crypt keys from a file. The format
// is to put a key per line as follows, (auth-algo auth-key enc-algo enc-key)
// Returns the authentication overhead in bytes, the key ID, and an error.
func (a *Agent) loadIPSecKeysFile(path string) (int, uint8, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	return a.LoadIPSecKeys(file)
}

func (a *Agent) LoadIPSecKeys(r io.Reader) (int, uint8, error) {
	var spi uint8
	var keyLen int

	a.ipSecLock.Lock()
	defer a.ipSecLock.Unlock()

	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		var (
			aeadKey    []byte
			authKey    []byte
			err        error
			offsetBase int
		)

		ipSecKey := &ipSecKey{
			ReqID: DefaultReqID,
		}

		// Scanning IPsec keys with one of the following formats:
		// 1. [spi] aead-algo aead-key icv-len
		// 2. [spi] auth-algo auth-key enc-algo enc-key [IP]
		s := strings.Split(scanner.Text(), " ")
		if len(s) < 3 {
			// Regardless of the format used, the IPsec secret should have at
			// least 3 fields separated by white spaces.
			return 0, 0, fmt.Errorf("missing IPSec key or invalid format")
		}

		spi, offsetBase, err = parseSPI(s[offsetSPI])
		if err != nil {
			return 0, 0, fmt.Errorf("failed to parse SPI: %w", err)
		}

		if len(s) > offsetBase+maxOffset+1 {
			return 0, 0, fmt.Errorf("invalid format: too many fields in the IPsec secret")
		} else if len(s) == offsetBase+offsetICV+1 {
			// We're in the first case, with "[spi] aead-algo aead-key icv-len".
			aeadName := s[offsetBase+offsetAeadAlgo]
			if !strings.HasPrefix(aeadName, "rfc") {
				return 0, 0, fmt.Errorf("invalid AEAD algorithm %q", aeadName)
			}

			_, aeadKey, err = decodeIPSecKey(s[offsetBase+offsetAeadKey])
			if err != nil {
				return 0, 0, fmt.Errorf("unable to decode AEAD key string %q", s[offsetBase+offsetAeadKey])
			}

			icvLen, err := strconv.Atoi(s[offsetICV+offsetBase])
			if err != nil {
				return 0, 0, fmt.Errorf("ICV length is invalid or missing")
			}

			if icvLen != 96 && icvLen != 128 && icvLen != 256 {
				return 0, 0, fmt.Errorf("only ICV lengths 96, 128, and 256 are accepted")
			}

			ipSecKey.Aead = &netlink.XfrmStateAlgo{
				Name:   aeadName,
				Key:    aeadKey,
				ICVLen: icvLen,
			}
			keyLen = icvLen / 8
		} else {
			// We're in the second case, with "[spi] auth-algo auth-key enc-algo enc-key [IP]".
			authAlgo := s[offsetBase+offsetAuthAlgo]
			keyLen, authKey, err = decodeIPSecKey(s[offsetBase+offsetAuthKey])
			if err != nil {
				return 0, 0, fmt.Errorf("unable to decode authentication key string %q", s[offsetBase+offsetAuthKey])
			}

			encAlgo := s[offsetBase+offsetEncAlgo]
			_, encKey, err := decodeIPSecKey(s[offsetBase+offsetEncKey])
			if err != nil {
				return 0, 0, fmt.Errorf("unable to decode encryption key string %q", s[offsetBase+offsetEncKey])
			}

			ipSecKey.Auth = &netlink.XfrmStateAlgo{
				Name: authAlgo,
				Key:  authKey,
			}
			ipSecKey.Crypt = &netlink.XfrmStateAlgo{
				Name: encAlgo,
				Key:  encKey,
			}
		}

		ipSecKey.Spi = spi
		ipSecKey.KeyLen = keyLen

		if oldKey, ok := a.ipSecKeysGlobal[""]; ok {
			if oldKey.Spi == spi {
				return 0, 0, fmt.Errorf("invalid SPI: changing IPSec keys requires incrementing the key id")
			}
			if oldKey.KeyLen != keyLen {
				return 0, 0, fmt.Errorf("invalid key rotation: key length must not change")
			}
			a.ipSecKeysRemovalTime[oldKey.Spi] = time.Now()
		}
		a.ipSecKeysGlobal[""] = ipSecKey
		a.ipSecCurrentKeySPI = spi
	}
	return keyLen, spi, nil
}

func parseSPI(spiStr string) (uint8, int, error) {
	if spiStr[len(spiStr)-1] == '+' {
		spiStr = spiStr[:len(spiStr)-1]
	}
	spi, err := strconv.Atoi(spiStr)
	if err != nil {
		return 0, 0, fmt.Errorf("the first argument of the IPsec secret is not a number. Attempted %q", spiStr)
	}
	if spi > linux_defaults.IPsecMaxKeyVersion {
		return 0, 0, fmt.Errorf("encryption key space exhausted. ID must be nonzero and less than %d. Attempted %q", linux_defaults.IPsecMaxKeyVersion+1, spiStr)
	}
	if spi == 0 {
		return 0, 0, fmt.Errorf("zero is not a valid key ID. ID must be nonzero and less than %d. Attempted %q", linux_defaults.IPsecMaxKeyVersion+1, spiStr)
	}
	return uint8(spi), 0, nil
}

func (a *Agent) setIPSecSPI(spi uint8) error {
	k := encrypt.EncryptKey{Key: 0}
	v := encrypt.EncryptValue{KeyID: spi}
	if err := a.encryptMap.Update(k, v); err != nil {
		a.log.Warn("cilium_encrypt_state map updated failed", logfields.Error, err)
		return err
	}
	a.spi = spi
	return nil
}

// deleteIPsecEncryptRoute removes nodes in main routing table by walking
// routes and matching route protocol type.
func (a *Agent) deleteIPsecEncryptRoute() {
	filter := &netlink.Route{
		Protocol: route.EncryptRouteProtocol,
	}

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := safenetlink.RouteListFiltered(family, filter, netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			a.log.Error("Unable to list ipsec encrypt routes", logfields.Error, err)
			return
		}

		for _, rt := range routes {
			if err := netlink.RouteDel(&rt); err != nil {
				a.log.Warn("Unable to delete ipsec encrypt route",
					logfields.Route, rt,
					logfields.Error, err,
				)
			}
		}
	}
}

func (a *Agent) keyfileWatcher(ctx context.Context, watcher *fswatcher.Watcher, keyfilePath string, nodeHandler types.NodeHandler, health cell.Health) error {
	for {
		select {
		case event := <-watcher.Events:
			if event.Op&(fswatcher.Create|fswatcher.Write) == 0 {
				continue
			}

			_, spi, err := a.loadIPSecKeysFile(keyfilePath)
			if err != nil {
				health.Degraded(fmt.Sprintf("Failed to load keyfile %q", keyfilePath), err)
				a.log.Error("Failed to load IPsec keyfile", logfields.Error, err)
				continue
			}

			// Update the IPSec key identity in the local node.
			// This will set addrs.ipsecKeyIdentity in the node
			// package, and eventually trigger an update to
			// publish the updated information to k8s/kvstore.
			a.localNode.Update(func(ln *node.LocalNode) {
				ln.EncryptionKey = spi
			})

			// AllNodeValidateImplementation will eventually call
			// nodeUpdate(), which is responsible for updating the
			// IPSec policies and states for all the different EPs
			// with ipsec.UpsertIPsecEndpoint()
			nodeHandler.AllNodeValidateImplementation()

			// Push SPI update into BPF datapath now that XFRM state
			// is configured.
			if err := a.setIPSecSPI(spi); err != nil {
				health.Degraded("Failed to set IPsec SPI", err)
				a.log.Error("Failed to set IPsec SPI", logfields.Error, err)
				continue
			}
			health.OK("Watching keyfiles")
		case err := <-watcher.Errors:
			a.log.Warn("Error encountered while watching file with fsnotify",
				logfields.Error, err,
				logfields.Path, keyfilePath,
			)

		case <-ctx.Done():
			health.Stopped("Context done")
			watcher.Close()
			return nil
		}
	}
}

func (a *Agent) startKeyfileWatcher(nodeHandler types.NodeHandler) error {
	if !a.config.EnableIPsecKeyWatcher {
		return nil
	}

	keyfilePath := a.config.IPsecKeyFile
	watcher, err := fswatcher.New(a.log, []string{keyfilePath})
	if err != nil {
		return err
	}

	a.jobs.Add(job.OneShot("keyfile-watcher", func(ctx context.Context, health cell.Health) error {
		return a.keyfileWatcher(ctx, watcher, keyfilePath, nodeHandler, health)
	}))

	return nil
}

// ipSecSPICanBeReclaimed is used to test whether a given SPI can be reclaimed
// or not (i.e. if it's not in use, and if not, if enough time has passed since
// when it was replaced by a newer one).
//
// In addition to the SPI, this function takes also a reclaimTimestamp
// parameter which represents the time at which we started reclaiming old keys.
// This is needed as we need to test the same SPI multiple times (since for any
// given SPI there are multiple policies and states associated with it), and we
// don't want to get inconsistent results because we are calling time.Now()
// directly in this function.
func (a *Agent) ipSecSPICanBeReclaimed(spi uint8, reclaimTimestamp time.Time) bool {
	// The SPI associated with the key currently in use should not be reclaimed
	if spi == a.ipSecCurrentKeySPI {
		return false
	}

	// Otherwise retrieve the time at which the key for the given SPI was removed
	keyRemovalTime, ok := a.ipSecKeysRemovalTime[spi]
	if !ok {
		// If not found in the keyRemovalTime map, assume the key was
		// deleted just now.
		// In this way if the agent gets restarted before an old key is
		// removed we will always wait at least IPsecKeyRotationDuration time
		// before reclaiming it
		a.ipSecKeysRemovalTime[spi] = time.Now()

		return false
	}

	// If the key was deleted less than the IPSec key deletion delay
	// time ago, it should not be reclaimed
	if reclaimTimestamp.Sub(keyRemovalTime) < a.config.IPsecKeyRotationDuration {
		return false
	}

	return true
}

func (a *Agent) deleteStaleXfrmStates(reclaimTimestamp time.Time) error {
	xfrmStateList, err := a.xfrmStateCache.XfrmStateList()
	if err != nil {
		return err
	}

	errs := resiliency.NewErrorSet("failed to delete stale xfrm states", len(xfrmStateList))
	for _, s := range xfrmStateList {
		stateSPI := uint8(s.Spi)
		if !a.ipSecSPICanBeReclaimed(stateSPI, reclaimTimestamp) {
			continue
		}
		if err := a.xfrmStateCache.XfrmStateDel(&s); err != nil {
			errs.Add(fmt.Errorf("failed to delete stale xfrm state spi (%d): %w", stateSPI, err))
		}
	}

	return errs.Error()
}

func (a *Agent) deleteStaleXfrmPolicies(reclaimTimestamp time.Time) error {
	xfrmPolicyList, err := safenetlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	errs := resiliency.NewErrorSet("failed to delete stale xfrm policies", len(xfrmPolicyList))
	for _, p := range xfrmPolicyList {
		policySPI := ipsec.GetSPIFromXfrmPolicy(&p)
		if !a.ipSecSPICanBeReclaimed(policySPI, reclaimTimestamp) {
			continue
		}

		// Only OUT XFRM policies depend on the SPI
		if p.Dir != netlink.XFRM_DIR_OUT {
			continue
		}

		if isDefaultDropPolicy(&p) {
			continue
		}

		a.log.Info("Deleting stale XFRM policy",
			logfields.SPI, a.ipSecCurrentKeySPI,
			logfields.OldSPI, policySPI,
			logfields.SourceIP, p.Src,
			logfields.DestinationIP, p.Dst,
			logfields.TrafficDirection, getDirFromXfrmMark(p.Mark),
			logfields.NodeID, getNodeIDAsHexFromXfrmMark(p.Mark),
		)
		if err := netlink.XfrmPolicyDel(&p); err != nil {
			errs.Add(fmt.Errorf("failed to delete stale xfrm policy spi (%d): %w", policySPI, err))
		}
	}

	return errs.Error()
}

func isDefaultDropPolicy(p *netlink.XfrmPolicy) bool {
	return equalDefaultDropPolicy(defaultDropPolicyIPv4, p) ||
		equalDefaultDropPolicy(defaultDropPolicyIPv6, p)
}

func equalDefaultDropPolicy(defaultDropPolicy, p *netlink.XfrmPolicy) bool {
	return p.Priority == defaultDropPolicy.Priority &&
		p.Action == defaultDropPolicy.Action &&
		p.Dir == defaultDropPolicy.Dir &&
		xfrmMarkEqual(p.Mark, defaultDropPolicy.Mark) &&
		p.Src.String() == defaultDropPolicy.Src.String() &&
		p.Dst.String() == defaultDropPolicy.Dst.String()
}

func (a *Agent) onTimer(ctx context.Context) error {
	a.ipSecLock.Lock()
	defer a.ipSecLock.Unlock()

	// In case no IPSec key has been loaded yet, don't try to reclaim any
	// old key
	if a.ipSecCurrentKeySPI == 0 {
		return nil
	}

	reclaimTimestamp := time.Now()

	if err := a.deleteStaleXfrmStates(reclaimTimestamp); err != nil {
		a.log.Warn("Failed to delete stale XFRM states",
			logfields.SPI, a.ipSecCurrentKeySPI,
			logfields.Error, err)
		return err
	}
	if err := a.deleteStaleXfrmPolicies(reclaimTimestamp); err != nil {
		a.log.Warn("Failed to delete stale XFRM policies",
			logfields.SPI, a.ipSecCurrentKeySPI,
			logfields.Error, err)
		return err
	}

	return nil
}

func NewTestIPsecAgent(tb testing.TB) *Agent {
	agent := &Agent{
		log:        hivetest.Logger(tb),
		localNode:  nil,
		jobs:       nil,
		encryptMap: fakeencryptmap.NewFakeEncryptMap(),

		authKeySize:          0,
		spi:                  0,
		ipSecKeysGlobal:      map[string]*ipSecKey{},
		ipSecKeysRemovalTime: map[uint8]time.Time{},
		xfrmStateCache:       NewXfrmStateListCache(time.Minute, true),
	}

	tb.Cleanup(func() {
		err := agent.DeleteXFRM(AllReqID)
		if err != nil {
			tb.Errorf("Failed cleaning XFRM state: %v", err)
		}
	})

	return agent
}
