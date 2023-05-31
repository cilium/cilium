// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package ipsec

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/fswatcher"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
)

type IPSecDir string

const (
	IPSecDirIn      IPSecDir = "IPSEC_IN"
	IPSecDirOut     IPSecDir = "IPSEC_OUT"
	IPSecDirBoth    IPSecDir = "IPSEC_BOTH"
	IPSecDirOutNode IPSecDir = "IPSEC_OUT_NODE"

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
	offsetIP       = 5
	maxOffset      = offsetIP

	// ipSecXfrmMarkSPIShift defines how many bits the SPI is shifted when
	// encoded in a XfrmMark
	ipSecXfrmMarkSPIShift = 12
)

type ipSecKey struct {
	Spi   uint8
	ReqID int
	Auth  *netlink.XfrmStateAlgo
	Crypt *netlink.XfrmStateAlgo
	Aead  *netlink.XfrmStateAlgo
}

var (
	ipSecLock lock.RWMutex

	// ipSecKeysGlobal can be accessed by multiple subsystems concurrently,
	// so it should be accessed only through the getIPSecKeys and
	// loadIPSecKeys functions, which will ensure the proper lock is held
	ipSecKeysGlobal = make(map[string]*ipSecKey)

	// ipSecCurrentKeySPI is the SPI of the IPSec currently in use
	ipSecCurrentKeySPI uint8

	// ipSecKeysRemovalTime is used to track at which time a given key is
	// replaced with a newer one, allowing to reclaim old keys only after
	// enough time has passed since their replacement
	ipSecKeysRemovalTime = make(map[uint8]time.Time)

	wildcardIPv4   = net.ParseIP("0.0.0.0")
	wildcardCIDRv4 = &net.IPNet{
		IP:   wildcardIPv4,
		Mask: net.IPv4Mask(0, 0, 0, 0),
	}
	wildcardIPv6   = net.ParseIP("0::0")
	wildcardCIDRv6 = &net.IPNet{
		IP:   wildcardIPv6,
		Mask: net.CIDRMask(128, 128),
	}

	defaultDropMark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkEncrypt,
		Mask:  linux_defaults.IPsecMarkMaskIn,
	}
	defaultDropPolicyIPv4 = &netlink.XfrmPolicy{
		Dir:      netlink.XFRM_DIR_OUT,
		Src:      wildcardCIDRv4,
		Dst:      wildcardCIDRv4,
		Mark:     defaultDropMark,
		Action:   netlink.XFRM_POLICY_BLOCK,
		Priority: 1,
	}
	defaultDropPolicyIPv6 = &netlink.XfrmPolicy{
		Dir:      netlink.XFRM_DIR_OUT,
		Src:      wildcardCIDRv6,
		Dst:      wildcardCIDRv6,
		Mark:     defaultDropMark,
		Action:   netlink.XFRM_POLICY_BLOCK,
		Priority: 1,
	}

	// To attempt to remove any stale XFRM configs once at startup, after
	// we've added the catch-all default-drop policy.
	removeStaleXFRMOnce sync.Once
)

func getIPSecKeys(ip net.IP) *ipSecKey {
	ipSecLock.RLock()
	defer ipSecLock.RUnlock()

	key, scoped := ipSecKeysGlobal[ip.String()]
	if scoped == false {
		key, _ = ipSecKeysGlobal[""]
	}
	return key
}

func ipSecNewState() *netlink.XfrmState {
	state := netlink.XfrmState{
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Proto: netlink.XFRM_PROTO_ESP,
		ESN:   false,
	}
	return &state
}

func ipSecNewPolicy() *netlink.XfrmPolicy {
	policy := netlink.XfrmPolicy{}
	return &policy
}

func ipSecAttachPolicyTempl(policy *netlink.XfrmPolicy, keys *ipSecKey, srcIP, dstIP net.IP, spi bool, optional int) {
	tmpl := netlink.XfrmPolicyTmpl{
		Proto:    netlink.XFRM_PROTO_ESP,
		Mode:     netlink.XFRM_MODE_TUNNEL,
		Reqid:    keys.ReqID,
		Dst:      dstIP,
		Src:      srcIP,
		Optional: optional,
	}

	if spi {
		tmpl.Spi = int(keys.Spi)
	}

	policy.Tmpls = append(policy.Tmpls, tmpl)
}

func ipSecJoinState(state *netlink.XfrmState, keys *ipSecKey) {
	if keys.Aead != nil {
		state.Aead = keys.Aead
	} else {
		state.Crypt = keys.Crypt
		state.Auth = keys.Auth
	}
	state.Spi = int(keys.Spi)
	state.Reqid = keys.ReqID
}

// xfrmStateReplace attempts to add a new XFRM state only if one doesn't
// already exist. If it doesn't but some other XFRM state conflicts, then
// we attempt to remove the conflicting state before trying to add again.
func xfrmStateReplace(new *netlink.XfrmState) error {
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("Cannot get XFRM state: %s", err)
	}

	// Check if the XFRM state already exists
	for _, s := range states {
		if xfrmIPEqual(s.Src, new.Src) && xfrmIPEqual(s.Dst, new.Dst) &&
			xfrmMarkEqual(s.OutputMark, new.OutputMark) &&
			xfrmMarkEqual(s.Mark, new.Mark) && s.Spi == new.Spi {
			return nil
		}
	}

	// It doesn't exist so let's attempt to add it.
	firstAttemptErr := netlink.XfrmStateAdd(new)
	if !os.IsExist(firstAttemptErr) {
		return firstAttemptErr
	}
	log.WithFields(logrus.Fields{
		logfields.SPI:           new.Spi,
		logfields.SourceIP:      new.Src,
		logfields.DestinationIP: new.Dst,
	}).Warn("Failed to add XFRM state due to conflicting state")

	// An existing state conflicts with this one. We need to remove the
	// existing one first.
	deletedSomething, err := xfrmDeleteConflictingState(states, new)
	if err != nil {
		return err
	}

	// If no conflicting state was found and deleted, there's no point in
	// attempting to add again.
	if !deletedSomething {
		return firstAttemptErr
	}
	return netlink.XfrmStateAdd(new)
}

// Attempt to remove any XFRM state that conflicts with the state we just tried
// to add. To find those conflicting states, we need to use the same logic that
// the kernel used to reject our check with EEXIST. That logic is upstream in
// __xfrm_state_lookup.
func xfrmDeleteConflictingState(states []netlink.XfrmState, new *netlink.XfrmState) (bool, error) {
	deletedSomething := false
	for _, s := range states {
		if new.Spi == s.Spi && (new.Mark == nil) == (s.Mark == nil) &&
			(new.Mark == nil || new.Mark.Value&new.Mark.Mask&s.Mark.Mask == s.Mark.Value) &&
			xfrmIPEqual(new.Src, s.Src) && xfrmIPEqual(new.Dst, s.Dst) {
			err := netlink.XfrmStateDel(&s)
			if err == nil {
				deletedSomething = true
				log.WithFields(logrus.Fields{
					logfields.SPI:           s.Spi,
					logfields.SourceIP:      s.Src,
					logfields.DestinationIP: s.Dst,
				}).Info("Removed a conflicting XFRM state")
			} else {
				return deletedSomething, fmt.Errorf("Failed to remove a conflicting XFRM state: %w", err)
			}
		}
	}
	return deletedSomething, nil
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

func ipSecReplaceStateIn(localIP, remoteIP net.IP, zeroMark bool) (uint8, error) {
	key := getIPSecKeys(remoteIP)
	if key == nil {
		return 0, fmt.Errorf("IPSec key missing")
	}
	state := ipSecNewState()
	ipSecJoinState(state, key)
	state.Src = remoteIP
	state.Dst = localIP
	state.Mark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkDecrypt,
		Mask:  linux_defaults.IPsecMarkMaskIn,
	}
	if !zeroMark {
		state.OutputMark = &netlink.XfrmMark{
			Value: linux_defaults.RouteMarkDecrypt,
			Mask:  linux_defaults.RouteMarkMask,
		}
	} else {
		state.OutputMark = &netlink.XfrmMark{
			Value: 0,
			Mask:  linux_defaults.RouteMarkMask,
		}
	}

	return key.Spi, xfrmStateReplace(state)
}

func ipSecReplaceStateOut(localIP, remoteIP net.IP, nodeID uint16) (uint8, error) {
	key := getIPSecKeys(localIP)
	if key == nil {
		return 0, fmt.Errorf("IPSec key missing")
	}
	state := ipSecNewState()
	ipSecJoinState(state, key)
	state.Src = localIP
	state.Dst = remoteIP
	state.Mark = generateEncryptMark(key.Spi, nodeID)
	state.OutputMark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkEncrypt,
		Mask:  linux_defaults.RouteMarkMask,
	}
	return key.Spi, xfrmStateReplace(state)
}

func _ipSecReplacePolicyInFwd(src, dst *net.IPNet, tmplSrc, tmplDst net.IP, proxyMark bool, dir netlink.Dir) error {
	optional := int(0)
	key := getIPSecKeys(dst.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}

	policy := ipSecNewPolicy()
	policy.Dir = dir
	policy.Dst = dst
	if dir == netlink.XFRM_DIR_IN {
		policy.Src = src
		policy.Mark = &netlink.XfrmMark{
			Mask: linux_defaults.IPsecMarkMaskIn,
		}
		if proxyMark {
			// We require a policy to match on packets going to the proxy which are
			// therefore carrying the proxy mark. We however don't need a policy
			// for the encrypted packets because there is already a state matching
			// them.
			policy.Mark.Value = linux_defaults.RouteMarkToProxy
			// We must mark the IN policy for the proxy optional simply because it
			// is lacking a corresponding state.
			optional = 1
			// We set the source tmpl address to 0/0 to explicit that it
			// doesn't matter.
			tmplSrc = net.ParseIP("0.0.0.0")
		} else {
			policy.Mark.Value = linux_defaults.RouteMarkDecrypt
		}
	}
	// We always make forward rules optional. The only reason we have these
	// at all is to appease the XFRM route hooks, we don't really care about
	// policy because Cilium BPF programs do that.
	if dir == netlink.XFRM_DIR_FWD {
		optional = 1
		policy.Priority = linux_defaults.IPsecFwdPriority
		// In case of fwd policies, we should tell the kernel the tmpl src
		// doesn't matter; we want all fwd packets to go through.
		tmplSrc = net.ParseIP("0.0.0.0")
		policy.Src = &net.IPNet{IP: tmplSrc, Mask: net.IPv4Mask(0, 0, 0, 0)}
	}
	ipSecAttachPolicyTempl(policy, key, tmplSrc, tmplDst, false, optional)
	return netlink.XfrmPolicyUpdate(policy)
}

func ipSecReplacePolicyIn(src, dst *net.IPNet, tmplSrc, tmplDst net.IP) error {
	if err := _ipSecReplacePolicyInFwd(src, dst, tmplSrc, tmplDst, true, netlink.XFRM_DIR_IN); err != nil {
		return err
	}
	return _ipSecReplacePolicyInFwd(src, dst, tmplSrc, tmplDst, false, netlink.XFRM_DIR_IN)
}

func IpSecReplacePolicyFwd(dst *net.IPNet, tmplDst net.IP) error {
	// The source CIDR and IP aren't used in the case of FWD policies.
	return _ipSecReplacePolicyInFwd(nil, dst, net.IP{}, tmplDst, false, netlink.XFRM_DIR_FWD)
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
func IPsecDefaultDropPolicy(ipv6 bool) (err error) {
	defaultDropPolicy := defaultDropPolicyIPv4
	family := netlink.FAMILY_V4
	if ipv6 {
		defaultDropPolicy = defaultDropPolicyIPv6
		family = netlink.FAMILY_V6
	}

	// We call removeStaleStatesAndPolicies only if the catch-all default-drop
	// policy was successfully installed. If it was not installed, then there's
	// a danger of letting plain-text traffic leave the node if we remove stale
	// XFRM configs.
	// This code can be removed in Cilium v1.15.
	defer func() {
		if err == nil {
			removeStaleStatesAndPolicies(family)
		}
	}()

	return netlink.XfrmPolicyUpdate(defaultDropPolicy)
}

// Removes XFRM states and policies that are identified as installed by a
// previous version of Cilium. We rely mainly on the mark mask to identify if
// it was installed in a previous version. These states and policies need to be
// removed for cross-node connectivity to work.
func removeStaleStatesAndPolicies(family int) {
	removeStaleXFRMOnce.Do(func() {
		removeStalePolicies(family)
		removeStaleStates(family)
	})
}

func removeStalePolicies(family int) {
	policies, err := netlink.XfrmPolicyList(family)
	if err != nil {
		log.WithError(err).Error("Cannot get XFRM policies")
	}
	for _, p := range policies {
		switch p.Dir {
		case netlink.XFRM_DIR_OUT:
			if isDefaultDropPolicy(&p) {
				continue
			}
			if p.Mark.Mask != linux_defaults.IPsecOldMarkMaskOut {
				// This XFRM OUT policy was not installed by a previous version of Cilium.
				continue
			}
		case netlink.XFRM_DIR_IN:
			// The XFRM IN policies didn't change so we don't want to remove them.
			continue
		default:
			continue
		}
		if err := netlink.XfrmPolicyDel(&p); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.SourceCIDR:      p.Src,
				logfields.DestinationCIDR: p.Dst,
			}).Error("Failed to remove stale XFRM policy")
		}
	}
}

func removeStaleStates(family int) {
	states, err := netlink.XfrmStateList(family)
	if err != nil {
		log.WithError(err).Error("Cannot get XFRM states")
	}
	for _, s := range states {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.SPI:           s.Spi,
			logfields.SourceIP:      s.Src,
			logfields.DestinationIP: s.Dst,
		})

		if s.Mark.Mask == linux_defaults.IPsecOldMarkMaskOut &&
			s.Mark.Value == ipSecXfrmMarkSetSPI(linux_defaults.RouteMarkEncrypt, uint8(s.Spi)) {
			// This XFRM state was installed by a previous version of Cilium.
			if err := netlink.XfrmStateDel(&s); err == nil {
				scopedLog.Info("Removed stale XFRM OUT state")
			} else {
				scopedLog.WithError(err).Error("Failed to remove stale XFRM OUT state")
			}
		}
	}
}

// ipSecXfrmMarkSetSPI takes a XfrmMark base value, an SPI, returns the mark
// value with the SPI value encoded in it
func ipSecXfrmMarkSetSPI(markValue uint32, spi uint8) uint32 {
	return markValue | (uint32(spi) << ipSecXfrmMarkSPIShift)
}

// ipSecXfrmMarkGetSPI extracts from a XfrmMark value the encoded SPI
func ipSecXfrmMarkGetSPI(markValue uint32) uint8 {
	return uint8(markValue >> ipSecXfrmMarkSPIShift & 0xF)
}

func getSPIFromXfrmPolicy(policy *netlink.XfrmPolicy) uint8 {
	if policy.Mark == nil {
		return 0
	}

	return ipSecXfrmMarkGetSPI(policy.Mark.Value)
}

func getNodeIDFromXfrmMark(mark *netlink.XfrmMark) uint16 {
	if mark == nil {
		return 0
	}
	return uint16(mark.Value >> 16)
}

func generateEncryptMark(spi uint8, nodeID uint16) *netlink.XfrmMark {
	val := ipSecXfrmMarkSetSPI(linux_defaults.RouteMarkEncrypt, spi)
	val |= uint32(nodeID) << 16
	return &netlink.XfrmMark{
		Value: val,
		Mask:  linux_defaults.IPsecMarkMaskOut,
	}
}

func ipSecReplacePolicyOut(src, dst *net.IPNet, tmplSrc, tmplDst net.IP, nodeID uint16, dir IPSecDir) error {
	// TODO: Remove old policy pointing to target net

	key := getIPSecKeys(dst.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}

	policy := ipSecNewPolicy()
	if dir == IPSecDirOutNode {
		policy.Src = wildcardCIDRv4
	} else {
		policy.Src = src
	}
	policy.Dst = dst
	policy.Dir = netlink.XFRM_DIR_OUT
	policy.Mark = generateEncryptMark(key.Spi, nodeID)
	ipSecAttachPolicyTempl(policy, key, tmplSrc, tmplDst, true, 0)
	return netlink.XfrmPolicyUpdate(policy)
}

func ipsecDeleteXfrmState(nodeID uint16) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeID: nodeID,
	})

	xfrmStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		scopedLog.WithError(err).Warning("Failed to list XFRM states for deletion")
		return
	}
	for _, s := range xfrmStateList {
		if getNodeIDFromXfrmMark(s.Mark) == nodeID {
			if err := netlink.XfrmStateDel(&s); err != nil {
				scopedLog.WithError(err).Warning("Failed to delete XFRM state")
			}
		}
	}
}

func ipsecDeleteXfrmPolicy(nodeID uint16) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeID: nodeID,
	})

	xfrmPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		scopedLog.WithError(err).Warning("Failed to list XFRM policies for deletion")
		return
	}
	for _, p := range xfrmPolicyList {
		if getNodeIDFromXfrmMark(p.Mark) == nodeID {
			if err := netlink.XfrmPolicyDel(&p); err != nil {
				scopedLog.WithError(err).Warning("Failed to delete XFRM policy")
			}
		}
	}
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
func UpsertIPsecEndpoint(local, remote *net.IPNet, outerLocal, outerRemote net.IP, remoteNodeID uint16, dir IPSecDir, outputMark bool) (uint8, error) {
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
	if !outerLocal.Equal(outerRemote) {
		if dir == IPSecDirIn || dir == IPSecDirBoth {
			if spi, err = ipSecReplaceStateIn(outerLocal, outerRemote, outputMark); err != nil {
				return 0, fmt.Errorf("unable to replace local state: %s", err)
			}
			if err = ipSecReplacePolicyIn(remote, local, outerRemote, outerLocal); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy in: %s", err)
				}
			}
			if err = IpSecReplacePolicyFwd(local, outerLocal); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy fwd: %s", err)
				}
			}
		}

		if dir == IPSecDirOut || dir == IPSecDirOutNode || dir == IPSecDirBoth {
			if spi, err = ipSecReplaceStateOut(outerLocal, outerRemote, remoteNodeID); err != nil {
				return 0, fmt.Errorf("unable to replace remote state: %s", err)
			}

			if err = ipSecReplacePolicyOut(local, remote, outerLocal, outerRemote, remoteNodeID, dir); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy out: %s", err)
				}
			}
		}
	}
	return spi, nil
}

// UpsertIPsecEndpointPolicy adds a policy to the xfrm rules. Used to add a policy when the state
// rule is already available.
func UpsertIPsecEndpointPolicy(local, remote *net.IPNet, localTmpl, remoteTmpl net.IP, remoteNodeID uint16, dir IPSecDir) error {
	if err := ipSecReplacePolicyOut(local, remote, localTmpl, remoteTmpl, remoteNodeID, dir); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to replace templated policy out: %s", err)
		}
	}
	return nil
}

// DeleteIPsecEndpoint deletes a endpoint associated with the remote IP address
func DeleteIPsecEndpoint(nodeID uint16) {
	ipsecDeleteXfrmState(nodeID)
	ipsecDeleteXfrmPolicy(nodeID)
}

func isXfrmPolicyCilium(policy netlink.XfrmPolicy) bool {
	if policy.Mark == nil {
		// Check if its our fwd rule, we don't have a mark
		// on this rule so use priority.
		if policy.Dir == netlink.XFRM_DIR_FWD &&
			policy.Priority == linux_defaults.IPsecFwdPriority {
			return true
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

// DeleteXfrm remove any remaining XFRM policy or state from tables
func DeleteXfrm() {
	xfrmPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err == nil {
		for _, p := range xfrmPolicyList {
			if isXfrmPolicyCilium(p) {
				if err := netlink.XfrmPolicyDel(&p); err != nil {
					log.WithError(err).Warning("deleting xfrm policy failed")
				}
			}
		}
	}
	xfrmStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err == nil {
		for _, s := range xfrmStateList {
			if isXfrmStateCilium(s) {
				if err := netlink.XfrmStateDel(&s); err != nil {
					log.WithError(err).Warning("deleting old xfrm state failed")
				}
			}
		}
	}
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

// LoadIPSecKeysFile imports IPSec auth and crypt keys from a file. The format
// is to put a key per line as follows, (auth-algo auth-key enc-algo enc-key)
// Returns the authentication overhead in bytes, the key ID, and an error.
func LoadIPSecKeysFile(path string) (int, uint8, error) {
	log.WithField(logfields.Path, path).Info("Loading IPsec keyfile")

	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	return loadIPSecKeys(file)
}

func loadIPSecKeys(r io.Reader) (int, uint8, error) {
	var spi uint8
	var keyLen int
	scopedLog := log

	ipSecLock.Lock()
	defer ipSecLock.Unlock()

	if err := encrypt.MapCreate(); err != nil {
		return 0, 0, fmt.Errorf("Encrypt map create failed: %v", err)
	}

	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		var oldSpi uint8
		var aeadKey, authKey []byte
		offsetBase := 0

		ipSecKey := &ipSecKey{
			ReqID: 1,
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

		spiI, err := strconv.Atoi(s[offsetSPI])
		if err != nil {
			// If no version info is provided assume using key format without
			// versioning and assign SPI.
			log.Warning("IPsec secrets without an SPI as the first argument are deprecated and will be unsupported in v1.13.")
			spiI = 1
			offsetBase = -1
		}
		if spiI > linux_defaults.IPsecMaxKeyVersion {
			return 0, 0, fmt.Errorf("encryption key space exhausted. ID must be nonzero and less than %d. Attempted %q", linux_defaults.IPsecMaxKeyVersion+1, s[offsetSPI])
		}
		if spiI == 0 {
			return 0, 0, fmt.Errorf("zero is not a valid key ID. ID must be nonzero and less than %d. Attempted %q", linux_defaults.IPsecMaxKeyVersion+1, s[offsetSPI])
		}
		spi = uint8(spiI)

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

		if len(s) == offsetBase+offsetIP+1 {
			// The IPsec secret has the optional IP address field at the end.
			log.Warning("IPsec secrets with an IP address as the last argument are deprecated and will be unsupported in v1.13.")
			if ipSecKeysGlobal[s[offsetBase+offsetIP]] != nil {
				oldSpi = ipSecKeysGlobal[s[offsetBase+offsetIP]].Spi
			}
			ipSecKeysGlobal[s[offsetBase+offsetIP]] = ipSecKey
		} else {
			if ipSecKeysGlobal[""] != nil {
				oldSpi = ipSecKeysGlobal[""].Spi
			}
			ipSecKeysGlobal[""] = ipSecKey
		}

		ipSecKeysRemovalTime[oldSpi] = time.Now()
		ipSecCurrentKeySPI = spi
	}
	if err := encrypt.MapUpdateContext(0, spi); err != nil {
		scopedLog.WithError(err).Warn("cilium_encrypt_state map updated failed:")
		return 0, 0, err
	}
	return keyLen, spi, nil
}

// DeleteIPsecEncryptRoute removes nodes in main routing table by walking
// routes and matching route protocol type.
func DeleteIPsecEncryptRoute() {
	filter := &netlink.Route{
		Protocol: route.EncryptRouteProtocol,
	}

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			log.WithError(err).Error("Unable to list direct routes")
			return
		}

		for _, rt := range routes {
			if err := netlink.RouteDel(&rt); err != nil {
				log.WithError(err).Warningf("Unable to delete direct node route %s", rt.String())
			}
		}
	}
}

func keyfileWatcher(ctx context.Context, watcher *fswatcher.Watcher, keyfilePath string, nodediscovery *nodediscovery.NodeDiscovery, nodeHandler datapath.NodeHandler) {
	for {
		select {
		case event := <-watcher.Events:
			if !event.Op.Has(fsnotify.Create) || !event.Op.Has(fsnotify.Write) {
				continue
			}

			_, spi, err := LoadIPSecKeysFile(keyfilePath)
			if err != nil {
				log.WithError(err).Errorf("Failed to load IPsec keyfile")
				continue
			}

			// Update the IPSec key identity in the local node.
			// This will set addrs.ipsecKeyIdentity in the node
			// package
			node.SetIPsecKeyIdentity(spi)

			// NodeValidateImplementation will eventually call
			// nodeUpdate(), which is responsible for updating the
			// IPSec policies and states for all the different EPs
			// with ipsec.UpsertIPsecEndpoint()
			nodeHandler.NodeValidateImplementation(*nodediscovery.LocalNode())

			// Publish the updated node information to k8s/KVStore
			nodediscovery.UpdateLocalNode()

		case err := <-watcher.Errors:
			log.WithError(err).WithField(logfields.Path, keyfilePath).
				Warning("Error encountered while watching file with fsnotify")

		case <-ctx.Done():
			watcher.Close()
			return
		}
	}
}

func StartKeyfileWatcher(ctx context.Context, keyfilePath string, nodediscovery *nodediscovery.NodeDiscovery, nodeHandler datapath.NodeHandler) error {
	watcher, err := fswatcher.New([]string{keyfilePath})
	if err != nil {
		return err
	}

	go keyfileWatcher(ctx, watcher, keyfilePath, nodediscovery, nodeHandler)

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
func ipSecSPICanBeReclaimed(spi uint8, reclaimTimestamp time.Time) bool {
	// The SPI associated with the key currently in use should not be reclaimed
	if spi == ipSecCurrentKeySPI {
		return false
	}

	// Otherwise retrieve the time at which the key for the given SPI was removed
	keyRemovalTime, ok := ipSecKeysRemovalTime[spi]
	if !ok {
		// If not found in the keyRemovalTime map, assume the key was
		// deleted just now.
		// In this way if the agent gets restarted before an old key is
		// removed we will always wait at least IPsecKeyRotationDuration time
		// before reclaiming it
		ipSecKeysRemovalTime[spi] = time.Now()

		return false
	}

	// If the key was deleted less than the IPSec key deletion delay
	// time ago, it should not be reclaimed
	if reclaimTimestamp.Sub(keyRemovalTime) < option.Config.IPsecKeyRotationDuration {
		return false
	}

	return true
}

func deleteStaleXfrmStates(reclaimTimestamp time.Time) {
	scopedLog := log.WithField(logfields.SPI, ipSecCurrentKeySPI)

	xfrmStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		scopedLog.WithError(err).Warning("Failed to list XFRM states")
		return
	}

	for _, s := range xfrmStateList {
		stateSPI := uint8(s.Spi)

		if !ipSecSPICanBeReclaimed(stateSPI, reclaimTimestamp) {
			continue
		}

		scopedLog = log.WithField(logfields.OldSPI, stateSPI)

		scopedLog.Info("Deleting stale XFRM state")
		if err := netlink.XfrmStateDel(&s); err != nil {
			scopedLog.WithError(err).Warning("Deleting stale XFRM state failed")
		}
	}
}

func deleteStaleXfrmPolicies(reclaimTimestamp time.Time) {
	scopedLog := log.WithField(logfields.SPI, ipSecCurrentKeySPI)

	xfrmPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		scopedLog.WithError(err).Warning("Failed to list XFRM policies")
		return
	}

	for _, p := range xfrmPolicyList {
		policySPI := getSPIFromXfrmPolicy(&p)

		if !ipSecSPICanBeReclaimed(policySPI, reclaimTimestamp) {
			continue
		}

		// Only OUT XFRM policies depend on the SPI
		if p.Dir != netlink.XFRM_DIR_OUT {
			continue
		}

		if isDefaultDropPolicy(&p) {
			continue
		}

		scopedLog = log.WithField(logfields.OldSPI, policySPI)

		scopedLog.Info("Deleting stale XFRM policy")
		if err := netlink.XfrmPolicyDel(&p); err != nil {
			scopedLog.WithError(err).Warning("Deleting stale XFRM policy failed")
		}
	}
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

func doReclaimStaleKeys() {
	ipSecLock.Lock()
	defer ipSecLock.Unlock()

	// In case no IPSec key has been loaded yet, don't try to reclaim any
	// old key
	if ipSecCurrentKeySPI == 0 {
		return
	}

	reclaimTimestamp := time.Now()

	deleteStaleXfrmStates(reclaimTimestamp)
	deleteStaleXfrmPolicies(reclaimTimestamp)
}

func StartStaleKeysReclaimer(ctx context.Context) {
	timer, timerDone := inctimer.New()

	go func() {
		for {
			select {
			case <-timer.After(1 * time.Minute):
				doReclaimStaleKeys()
			case <-ctx.Done():
				timerDone()
				return
			}
		}
	}()
}
