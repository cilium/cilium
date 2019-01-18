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
	"net"
	"os"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/vishvananda/netlink"

	"github.com/sirupsen/logrus"
)

type ipSecKey struct {
	Spi   int
	ReqID int
	Auth  *netlink.XfrmStateAlgo
	Crypt *netlink.XfrmStateAlgo
}

var ipSecKeysGlobal = make(map[string]*ipSecKey)

func getIpSecKeys(ip net.IP) *ipSecKey {
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

func ipSecAttachPolicyTempl(policy *netlink.XfrmPolicy, keys *ipSecKey, srcIP net.IP, dstIP net.IP) {
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

func ipSecGetLocalIP(endpointIP net.IP) net.IP {
	if endpointIP.To4() != nil {
		return node.GetInternalIPv4()
	}
	return node.GetIPv6Router()
}

func ipSecReplaceState(remoteIP, localIP net.IP) error {
	state := ipSecNewState()

	ipSecJoinState(state, getIpSecKeys(localIP))
	state.Src = localIP
	state.Dst = remoteIP
	err := netlink.XfrmStateAdd(state)
	return err
}

func ipSecReplacePolicy(endpoint, remoteCilium, localCilium net.IP) {
	/* Errors are ignored at the moment due to expecting EEXIST errors */
	ipSecReplacePolicyIn(endpoint, remoteCilium, localCilium)
	ipSecReplacePolicyOut(endpoint, remoteCilium, localCilium)
}

func ipSecReplacePolicyIn(endpoint, remoteCilium, localCilium net.IP) error {
	ipSecReplacePolicyInFwd(endpoint, remoteCilium, localCilium, netlink.XFRM_DIR_IN)
	return ipSecReplacePolicyInFwd(endpoint, remoteCilium, localCilium, netlink.XFRM_DIR_FWD)
}

func ipSecReplacePolicyInFwd(endpoint, remoteCilium, localCilium net.IP, dir netlink.Dir) error {
	policy := ipSecNewPolicy()
	policy.Dir = dir
	policy.Src = &net.IPNet{
		IP:   remoteCilium,
		Mask: net.IPv4Mask(255, 255, 0, 0),
	}
	policy.Dst = &net.IPNet{
		IP:   localCilium,
		Mask: net.IPv4Mask(255, 255, 0, 0),
	}
	policy.Mark = &netlink.XfrmMark{
		Value: 0x0D00,
		Mask:  0x0F00,
	}
	ipSecAttachPolicyTempl(policy, getIpSecKeys(remoteCilium), remoteCilium, localCilium)
	return netlink.XfrmPolicyUpdate(policy)
}

func ipSecReplacePolicyOut(endpoint, remoteCilium, localCilium net.IP) error {
	policy := ipSecNewPolicy()
	policy.Dir = netlink.XFRM_DIR_OUT
	policy.Src = &net.IPNet{
		IP:   node.GetInternalIPv4(),
		Mask: net.IPv4Mask(255, 255, 0, 0),
	}
	policy.Dst = &net.IPNet{
		IP:   remoteCilium,
		Mask: net.IPv4Mask(255, 255, 0, 0),
	}
	policy.Mark = &netlink.XfrmMark{
		Value: 0x0E00,
		Mask:  0x0F00,
	}
	ipSecAttachPolicyTempl(policy, getIpSecKeys(localCilium), localCilium, remoteCilium)
	return netlink.XfrmPolicyUpdate(policy)
}

func ipSecDeleteStateOut(endpointIP net.IP) error {
	state := ipSecNewState()
	local := ipSecGetLocalIP(endpointIP)

	state.Src = endpointIP
	state.Dst = local
	err := netlink.XfrmStateDel(state)
	return err
}

func ipSecDeleteStateIn(endpointIP net.IP) error {
	state := ipSecNewState()
	local := ipSecGetLocalIP(endpointIP)

	state.Src = endpointIP
	state.Dst = local
	err := netlink.XfrmStateDel(state)
	return err
}

func ipSecDeletePolicy(endpointIP net.IP) error {
	return nil
}

/* UpsertIPSecEndpoint updates the IPSec context for a new endpoint inserted in
 * the ipcache. Currently we support a global crpyt/auth keyset that will encrypt
 * all traffic between endpoints. An IPSec context consists of two pieces a policy
 * and a state. These are implemented using the Linux kernels xfrm implementation.
 *
 * For all traffic that matches a policy, the policy tuple used is
 * (sip/mask, dip/mask, dev), the state hashtable is searched for a matching state
 * associated with that flow. The Linux kernel will do a series of hash lookups to
 * find the most specific state (xfrm_dst) possible. The hash keys searched are
 * the following, (daddr, saddr, reqid, encap_family), (daddr, wildcard, reqid, encap),
 * (mark, daddr, spi, proto, encap). Any "hits" in the hash table will subsequently
 * have the SPI checked to ensure it also matches. Encap is ignored in our case here
 * and can be used with UDP encap if wanted.
 *
 * The implications of the (inflexible) hash key implementation is that in-order
 * to have a policy/state match we _must_ insert a state for each daddr. For Cilium
 * this translates to a state entry per remote endpoint in the non-tunneled IPSec
 * case. In the tunneled case we can use the outer IP address reducing the entries
 * to the number of remote nodes. In either case we learn the endpoints by
 * listening to ipcache events. Finally, because IPSec is unidirectional a state
 * is needed for both ingress and egress. Denoted by the DIR on the xfrm cmd line
 * in the policy lookup. In the Cilium case, where we have IPSec between all
 * endpoints this results in three policy rules per endpoint, one for ingress
 * and one for egress. The third rule is a forward rule, describe later.
 *
 * For a concrete example consider two cluster nodes using transparent mode e.g.
 * without an IPSec tunnel IP. Cluster Node A has host_ip 10.156.0.1 with an
 * endpoint assigned to IP 10.156.2.2 and cluster Node B has host_ip 10.182.0.1
 * with an endpoint using IP 10.182.3.3. Then on Node A there will be a two policy
 * entries and a set of State entries per endpoint,
 *
 * Policy1(src=10.182.0.0/16,dst=10.156.0.1/16,dir=in,tmpl(spi=#spi,reqid=#reqid))
 * Policy2(src=10.156.0.0/16,dst=10.182.0.1/16,dir=out,tmpl(spi=#spi,reqid=#reqid))
 * State1(src=*,dst=10.182.3.3,spi=#spi,reqid=#reqid,...)
 * State2(src=*,dst=10.156.2.2,spi=#spi,reqid=#reqid,...)
 * State3(src=*,dst=10.156.0.1,spi=#spi,reqid=#reqid,...)
 *
 * Each additional local endpoint will need a rule similar to State2 and each
 * remote endpoint will need an entry similar to State1. Total number of State
 * rules is 'number_of_local_endpoints + number_of_remote_endpoints + 1'. Total
 * number of policy rules is 'number of clusters x 2'. When in tunnel mode only
 * two state entries would be needed per node.
 *
 * Design Note: For newer kernels a BPF xfrm interface would greatly simplify the
 * state space. Basic idea would be to reference a state using any key generated
 * from BPF program allowing for a single state per host node.
 */
func UpsertIPSecEndpoint(endpoint net.IPNet, ciliumIP net.IP) error {
	/* TODO: state reference ID is (dip,spi) which can be duplicated in the current global
	 * mode. The duplication is on _all_ ingress states because dst_ip == host_ip in this
	 * case and only a single spi entry is in use. Currently no check is done to avoid
	 * attempting to add duplicate (dip,spi) states and we get 'file exist' error. These
	 * errors are expected at the moment but perhaps it would be better to avoid calling
	 * netlink API at all when we "know" an entry is a duplicate. To do this the xfer
	 * state would need to be cached in the ipcache.
	 */

	/* We need to ensure that replies of packets that were routed through cilium_host
	 * will be encrypted as well. These packets have (sip=<local ep>,dip=<remote host>)
	 */
	if ciliumIP != nil {
		localCilium := node.GetInternalIPv4()

		/* The two states plus policy below is sufficient for tunnel mode for
		 * transparent mode ciliumIP == nil case must also be handled.
		 */
		if !ciliumIP.Equal(localCilium) {
			ipSecReplaceState(ciliumIP, localCilium)
			ipSecReplaceState(localCilium, ciliumIP)
			ipSecReplacePolicy(ciliumIP, ciliumIP, localCilium)
		}
	}
	return nil
}

// DeleteIPSecEndpoint deletes the endpoint from IPSec tables/routes
func DeleteIPSecEndpoint(endpointIP net.IP) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr: endpointIP,
	})

	err := ipSecDeleteStateIn(endpointIP)
	if err != nil {
		scopedLog.WithError(err).Warning("unable to delete IPSec (stateIn) context\n")
	}
	err = ipSecDeleteStateOut(endpointIP)
	if err != nil {
		scopedLog.WithError(err).Warning("unable to delete IPSec (stateOut) context\n")
	}
	err = ipSecDeletePolicy(endpointIP)
	if err != nil {
		scopedLog.WithError(err).Warning("unable to delete IPSec (policy) context\n")
	}
	return nil
}

func LoadIPSecKeysFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		ipSecKey := &ipSecKey{
			Spi:   1,
			ReqID: 1,
		}

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
			fmt.Printf("auth %s %s enc %s %s scope %s\n", authname, authkey, encname, enckey, s[4])
			ipSecKeysGlobal[s[4]] = ipSecKey
		} else {
			fmt.Printf("auth %s %s enc %s %s scope <default>\n", authname, authkey, encname, enckey)
			ipSecKeysGlobal[""] = ipSecKey
		}
	}
	return nil
}
