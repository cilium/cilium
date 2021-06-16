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
//
// +build linux

package ipsec

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/maps/encrypt"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type IPSecDir string

const (
	IPSecDirIn      IPSecDir = "IPSEC_IN"
	IPSecDirOut     IPSecDir = "IPSEC_OUT"
	IPSecDirBoth    IPSecDir = "IPSEC_BOTH"
	IPSecDirOutNode IPSecDir = "IPSEC_OUT_NODE"
)

type ipSecKey struct {
	Spi   uint8
	ReqID int
	Auth  *netlink.XfrmStateAlgo
	Crypt *netlink.XfrmStateAlgo
	Aead  *netlink.XfrmStateAlgo
}

// ipSecKeysGlobal is safe to read unlocked because the only writers are from
// daemon init time before any readers will be online.
var ipSecKeysGlobal = make(map[string]*ipSecKey)

func getIPSecKeys(ip net.IP) *ipSecKey {
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

func ipSecReplaceStateIn(remoteIP, localIP net.IP, zeroMark bool) (uint8, error) {
	key := getIPSecKeys(localIP)
	if key == nil {
		return 0, fmt.Errorf("IPSec key missing")
	}
	state := ipSecNewState()
	ipSecJoinState(state, key)
	state.Src = localIP
	state.Dst = remoteIP
	state.Mark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkDecrypt,
		Mask:  linux_defaults.IPsecMarkMaskIn,
	}
	if zeroMark != true {
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

	return key.Spi, netlink.XfrmStateAdd(state)
}

func ipSecReplaceStateOut(remoteIP, localIP net.IP) (uint8, error) {
	key := getIPSecKeys(localIP)
	if key == nil {
		return 0, fmt.Errorf("IPSec key missing")
	}
	spiWide := uint32(key.Spi)
	state := ipSecNewState()
	ipSecJoinState(state, key)
	state.Src = localIP
	state.Dst = remoteIP
	state.Mark = &netlink.XfrmMark{
		Value: ((spiWide << 12) | linux_defaults.RouteMarkEncrypt),
		Mask:  linux_defaults.IPsecMarkMask,
	}
	state.OutputMark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkEncrypt,
		Mask:  linux_defaults.RouteMarkMask,
	}
	return key.Spi, netlink.XfrmStateAdd(state)
}

func _ipSecReplacePolicyInFwd(src, dst, tmplSrc, tmplDst *net.IPNet, tunnel bool, dir netlink.Dir) error {
	optional := int(0)
	key := getIPSecKeys(dst.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}

	policy := ipSecNewPolicy()
	policy.Dir = dir
	policy.Src = &net.IPNet{IP: src.IP.Mask(src.Mask), Mask: src.Mask}
	policy.Dst = &net.IPNet{IP: dst.IP.Mask(dst.Mask), Mask: dst.Mask}
	if dir == netlink.XFRM_DIR_IN {
		policy.Mark = &netlink.XfrmMark{
			Mask: linux_defaults.IPsecMarkMaskIn,
		}
		if tunnel {
			// Required as this policy with the following mark does not have a
			// corresponding XFRM state matching it. The XFRM state for Dir=In
			// has mark for decryption only. If we don't mark this optional,
			// then we'll get a packet drop with the reason as
			// XfrmInTmplMismatch.
			optional = 1
			policy.Mark.Value = linux_defaults.RouteMarkToProxy
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
	}
	ipSecAttachPolicyTempl(policy, key, tmplSrc.IP, tmplDst.IP, false, optional)
	return netlink.XfrmPolicyUpdate(policy)
}

func ipSecReplacePolicyIn(src, dst, tmplSrc, tmplDst *net.IPNet, tunnel bool) error {
	// In the case that Cilium is running in tunneling mode, we insert an
	// additional In rule. It's for allowing traffic to the proxy in the
	// case of L7 ingress.
	if tunnel {
		if err := _ipSecReplacePolicyInFwd(src, dst, tmplSrc, tmplDst, tunnel, netlink.XFRM_DIR_IN); err != nil {
			return err
		}
	}
	return _ipSecReplacePolicyInFwd(src, dst, tmplSrc, tmplDst, false, netlink.XFRM_DIR_IN)
}

func IpSecReplacePolicyFwd(src, dst, tmplSrc, tmplDst *net.IPNet) error {
	return _ipSecReplacePolicyInFwd(src, dst, tmplSrc, tmplDst, false, netlink.XFRM_DIR_FWD)
}

func ipSecReplacePolicyOut(src, dst, tmplSrc, tmplDst *net.IPNet, dir IPSecDir) error {
	// TODO: Remove old policy pointing to target net
	var spiWide uint32

	key := getIPSecKeys(dst.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}
	spiWide = uint32(key.Spi)

	policy := ipSecNewPolicy()
	if dir == IPSecDirOutNode {
		wildcardIP := net.ParseIP("0.0.0.0")
		wildcardMask := net.IPv4Mask(0, 0, 0, 0)
		policy.Src = &net.IPNet{IP: wildcardIP, Mask: wildcardMask}
	} else {
		policy.Src = &net.IPNet{IP: src.IP.Mask(src.Mask), Mask: src.Mask}
	}
	policy.Dst = &net.IPNet{IP: dst.IP.Mask(dst.Mask), Mask: dst.Mask}
	policy.Dir = netlink.XFRM_DIR_OUT
	policy.Mark = &netlink.XfrmMark{
		Value: ((spiWide << 12) | linux_defaults.RouteMarkEncrypt),
		Mask:  linux_defaults.IPsecMarkMask,
	}
	ipSecAttachPolicyTempl(policy, key, tmplSrc.IP, tmplDst.IP, true, 0)
	return netlink.XfrmPolicyUpdate(policy)
}

func ipsecDeleteXfrmSpi(spi uint8) {
	var err error
	scopedLog := log.WithFields(logrus.Fields{
		"spi": spi,
	})

	xfrmStateList, err := netlink.XfrmStateList(0)
	if err != nil {
		scopedLog.WithError(err).Warning("deleting previous SPI, xfrm state list error")
		return
	}
	for _, s := range xfrmStateList {
		if s.Spi != int(spi) {
			if err := netlink.XfrmStateDel(&s); err != nil {
				scopedLog.WithError(err).Warning("deleting old xfrm state failed")
			}
		}
	}
}

func ipsecDeleteXfrmState(ip net.IP) {
	scopedLog := log.WithFields(logrus.Fields{
		"remote-ip": ip,
	})

	xfrmStateList, err := netlink.XfrmStateList(0)
	if err != nil {
		scopedLog.WithError(err).Warning("deleting xfrm state, xfrm state list error")
		return
	}
	for _, s := range xfrmStateList {
		if ip.Equal(s.Dst) {
			if err := netlink.XfrmStateDel(&s); err != nil {
				scopedLog.WithError(err).Warning("deleting xfrm state failed")
			}
		}
	}
}

func ipsecDeleteXfrmPolicy(ip net.IP) {
	scopedLog := log.WithFields(logrus.Fields{
		"remote-ip": ip,
	})

	xfrmPolicyList, err := netlink.XfrmPolicyList(0)
	if err != nil {
		scopedLog.WithError(err).Warning("deleting policy state, xfrm policy list error")
	}
	for _, p := range xfrmPolicyList {
		if ip.Equal(p.Dst.IP) {
			if err := netlink.XfrmPolicyDel(&p); err != nil {
				scopedLog.WithError(err).Warning("deleting xfrm policy failed")
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
func UpsertIPsecEndpoint(local, remote, fwd *net.IPNet, dir IPSecDir, outputMark, tunnel bool) (uint8, error) {
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
	/* The two states plus policy below is sufficient for tunnel mode for
	 * transparent mode ciliumIP == nil case must also be handled.
	 */
	if !local.IP.Equal(remote.IP) {
		if dir == IPSecDirIn || dir == IPSecDirBoth {
			if spi, err = ipSecReplaceStateIn(local.IP, remote.IP, outputMark); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace local state: %s", err)
				}
			}
			if err = ipSecReplacePolicyIn(remote, local, remote, local, tunnel); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy in: %s", err)
				}
			}
			if err = IpSecReplacePolicyFwd(remote, fwd, remote, local); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy fwd: %s", err)
				}
			}
		}

		if dir == IPSecDirOut || dir == IPSecDirOutNode || dir == IPSecDirBoth {
			if spi, err = ipSecReplaceStateOut(remote.IP, local.IP); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace remote state: %s", err)
				}
			}

			if err = ipSecReplacePolicyOut(local, remote, local, remote, dir); err != nil {
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
func UpsertIPsecEndpointPolicy(local, remote, localTmpl, remoteTmpl *net.IPNet, dir IPSecDir) error {
	if err := ipSecReplacePolicyOut(local, remote, localTmpl, remoteTmpl, dir); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to replace templated policy out: %s", err)
		}
	}
	return nil
}

// DeleteIPsecEndpoint deletes a endpoint associated with the remote IP address
func DeleteIPsecEndpoint(remote *net.IPNet) {
	ipsecDeleteXfrmState(remote.IP)
	ipsecDeleteXfrmPolicy(remote.IP)
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
	xfrmPolicyList, err := netlink.XfrmPolicyList(0)
	if err == nil {
		for _, p := range xfrmPolicyList {
			if isXfrmPolicyCilium(p) {
				if err := netlink.XfrmPolicyDel(&p); err != nil {
					log.WithError(err).Warning("deleting xfrm policy failed")
				}
			}
		}
	}
	xfrmStateList, err := netlink.XfrmStateList(0)
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

	if err := encrypt.MapCreate(); err != nil {
		return 0, 0, fmt.Errorf("Encrypt map create failed: %v", err)
	}

	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		var oldSpi uint8
		var authkey []byte
		offset := 0

		ipSecKey := &ipSecKey{
			ReqID: 1,
		}

		// Scanning IPsec keys formatted as follows,
		//    auth-algo auth-key enc-algo enc-key
		s := strings.Split(scanner.Text(), " ")
		if len(s) < 2 {
			return 0, 0, fmt.Errorf("missing IPSec keys or invalid format")
		}

		spiI, err := strconv.Atoi(s[0])
		if err != nil {
			// If no version info is provided assume using key format without
			// versioning and assign SPI.
			spiI = 1
			offset = -1
		}
		if spiI > linux_defaults.IPsecMaxKeyVersion {
			return 0, 0, fmt.Errorf("encryption Key space exhausted, id must be nonzero and less than %d. Attempted %q", linux_defaults.IPsecMaxKeyVersion, s[0])
		}
		if spiI == 0 {
			return 0, 0, fmt.Errorf("zero is not a valid key to disable encryption use `--enable-ipsec=false`, id must be nonzero and less than %d. Attempted %q", linux_defaults.IPsecMaxKeyVersion, s[0])
		}
		spi = uint8(spiI)

		keyLen, authkey, err = decodeIPSecKey(s[2+offset])
		if err != nil {
			return 0, 0, fmt.Errorf("unable to decode authkey string %q", s[1+offset])
		}
		authname := s[1+offset]

		if strings.HasPrefix(authname, "rfc") {
			icvLen, err := strconv.Atoi(s[3+offset])
			if err != nil {
				return 0, 0, fmt.Errorf("ICVLen is invalid or missing")
			}

			if icvLen != 96 && icvLen != 128 && icvLen != 256 {
				return 0, 0, fmt.Errorf("Unknown ICVLen accepts 96, 128, 256")
			}

			ipSecKey.Aead = &netlink.XfrmStateAlgo{
				Name:   authname,
				Key:    authkey,
				ICVLen: icvLen,
			}
			keyLen = icvLen / 8
		} else {
			_, enckey, err := decodeIPSecKey(s[4+offset])
			if err != nil {
				return 0, 0, fmt.Errorf("unable to decode enckey string %q", s[3+offset])
			}

			encname := s[3+offset]

			ipSecKey.Auth = &netlink.XfrmStateAlgo{
				Name: authname,
				Key:  authkey,
			}
			ipSecKey.Crypt = &netlink.XfrmStateAlgo{
				Name: encname,
				Key:  enckey,
			}
		}

		ipSecKey.Spi = spi

		if len(s) == 6+offset {
			if ipSecKeysGlobal[s[5+offset]] != nil {
				oldSpi = ipSecKeysGlobal[s[5+offset]].Spi
			}
			ipSecKeysGlobal[s[5+offset]] = ipSecKey
		} else {
			if ipSecKeysGlobal[""] != nil {
				oldSpi = ipSecKeysGlobal[""].Spi
			}
			ipSecKeysGlobal[""] = ipSecKey
		}

		scopedLog := log.WithFields(logrus.Fields{
			"oldSPI": oldSpi,
			"SPI":    spi,
		})

		// Detect a version change and call cleanup routine to remove old
		// keys after a timeout period. We also want to ensure on restart
		// we remove any stale keys for example when a restart changes keys.
		// In the restart case oldSpi will be '0' and cause the delete logic
		// to run.
		if oldSpi != ipSecKey.Spi {
			go func() {
				time.Sleep(linux_defaults.IPsecKeyDeleteDelay)
				scopedLog.Info("New encryption keys reclaiming SPI")
				ipsecDeleteXfrmSpi(ipSecKey.Spi)
			}()
		}
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
