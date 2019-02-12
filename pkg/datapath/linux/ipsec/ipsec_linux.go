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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/vishvananda/netlink"

	"github.com/sirupsen/logrus"
)

type ipSecKey struct {
	Spi   int
	ReqID int
	Auth  *netlink.XfrmStateAlgo
	Crypt *netlink.XfrmStateAlgo
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

func ipSecAttachPolicyTempl(policy *netlink.XfrmPolicy, keys *ipSecKey, srcIP, dstIP net.IP) {
	tmpl := netlink.XfrmPolicyTmpl{
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   keys.Spi,
		Reqid: keys.ReqID,
		Dst:   dstIP,
		Src:   srcIP,
	}

	policy.Tmpls = append(policy.Tmpls, tmpl)
}

func ipSecJoinState(state *netlink.XfrmState, keys *ipSecKey) {
	state.Auth = keys.Auth
	state.Crypt = keys.Crypt
	state.Spi = keys.Spi
	state.Reqid = keys.ReqID
}

func ipSecReplaceState(remoteIP, localIP net.IP, spi int) error {
	state := ipSecNewState()

	key := getIPSecKeys(localIP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}
	key.Spi = spi
	ipSecJoinState(state, key)
	state.Src = localIP
	state.Dst = remoteIP
	return netlink.XfrmStateAdd(state)
}

func ipSecReplacePolicyIn(src, dst *net.IPNet) error {
	if err := ipSecReplacePolicyInFwd(src, dst, netlink.XFRM_DIR_IN); err != nil {
		if !os.IsExist(err) {
			return err
		}
	}
	return ipSecReplacePolicyInFwd(src, dst, netlink.XFRM_DIR_FWD)
}

func ipSecReplacePolicyInFwd(src, dst *net.IPNet, dir netlink.Dir) error {
	policy := ipSecNewPolicy()
	policy.Dir = dir
	policy.Src = src
	policy.Dst = dst
	policy.Mark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkDecrypt,
		Mask:  linux_defaults.RouteMarkMask,
	}

	key := getIPSecKeys(dst.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}
	ipSecAttachPolicyTempl(policy, key, src.IP, dst.IP)
	return netlink.XfrmPolicyUpdate(policy)
}

func ipSecReplacePolicyOut(src, dst *net.IPNet) error {
	policy := ipSecNewPolicy()
	policy.Dir = netlink.XFRM_DIR_OUT
	policy.Src = src
	policy.Dst = dst
	policy.Mark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkEncrypt,
		Mask:  linux_defaults.RouteMarkMask,
	}
	key := getIPSecKeys(dst.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}
	ipSecAttachPolicyTempl(policy, key, src.IP, dst.IP)
	return netlink.XfrmPolicyUpdate(policy)
}

func ipSecDeleteStateOut(src, local net.IP) error {
	state := ipSecNewState()

	state.Src = src
	state.Dst = local
	err := netlink.XfrmStateDel(state)
	return err
}

func ipSecDeleteStateIn(src, local net.IP) error {
	state := ipSecNewState()

	state.Src = src
	state.Dst = local
	err := netlink.XfrmStateDel(state)
	return err
}

func ipSecDeletePolicy(src, local net.IP) error {
	return nil
}

/* UpsertIPSecEndpoint updates the IPSec context for a new endpoint inserted in
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
func UpsertIPSecEndpoint(local, remote *net.IPNet, spi int) error {
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
		if err := ipSecReplaceState(local.IP, remote.IP, spi); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("unable to replace local state: %s", err)
			}
		}
		if err := ipSecReplaceState(remote.IP, local.IP, spi); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("unable to replace remote state: %s", err)
			}
		}
		if err := ipSecReplacePolicyOut(local, remote); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("unable to replace policy out: %s", err)
			}
		}
		if err := ipSecReplacePolicyIn(remote, local); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("unable to replace policy in: %s", err)
			}
		}
	}
	return nil
}

// DeleteIPSecEndpoint deletes the endpoint from IPSec SPD and SAD
func DeleteIPSecEndpoint(src, local net.IP) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr: src,
	})

	err := ipSecDeleteStateIn(src, local)
	if err != nil {
		scopedLog.WithError(err).Warning("unable to delete IPSec (stateIn) context\n")
	}
	err = ipSecDeleteStateOut(src, local)
	if err != nil {
		scopedLog.WithError(err).Warning("unable to delete IPSec (stateOut) context\n")
	}
	err = ipSecDeletePolicy(src, local)
	if err != nil {
		scopedLog.WithError(err).Warning("unable to delete IPSec (policy) context\n")
	}
	return nil
}

// LoadIPSecKeysFile imports IPSec auth and crypt keys from a file. The format
// is to put a key per line as follows, (auth-algo auth-key enc-algo enc-key)
func LoadIPSecKeysFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to load IPSec Keys File %s: %v", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		ipSecKey := &ipSecKey{
			Spi:   1,
			ReqID: 1,
		}

		// Scanning IPsec keys formatted as follows,
		//    auth-algo auth-key enc-algo enc-key
		s := strings.Split(scanner.Text(), " ")
		if len(s) < 4 {
			return fmt.Errorf("missing IPSec keys or invalid format")
		}

		authname, authkey := s[0], []byte(s[1])
		encname, enckey := s[2], []byte(s[3])

		ipSecKey.Auth = &netlink.XfrmStateAlgo{
			Name: authname,
			Key:  authkey,
		}
		ipSecKey.Crypt = &netlink.XfrmStateAlgo{
			Name: encname,
			Key:  enckey,
		}
		if len(s) == 5 {
			ipSecKeysGlobal[s[4]] = ipSecKey
		} else {
			ipSecKeysGlobal[""] = ipSecKey
		}
	}
	return nil
}

// EnableIPv6Forwarding sets proc file to enable IPv6 forwarding
func EnableIPv6Forwarding() error {
	ip6ConfPath := "/proc/sys/net/ipv6/conf/"
	device := "all"
	forwarding := "forwarding"
	forwardingOn := "1"
	path := filepath.Join(ip6ConfPath, device, forwarding)
	return ioutil.WriteFile(path, []byte(forwardingOn), 0644)
}
