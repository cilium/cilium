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
//
// +build linux

package ipsec

import (
	"encoding/hex"
	"errors"
	"net"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"

	"github.com/vishvananda/netlink"
)

const (
	dummyIP  = "169.254.169.254"
	aeadKey  = "4242424242424242424242424242424242424242"
	aeadAlgo = "rfc4106(gcm(aes))"
	stateId  = 42
)

func initDummyXfrmState() *netlink.XfrmState {
	state := ipSecNewState()

	k, _ := hex.DecodeString(aeadKey)
	state.Aead = &netlink.XfrmStateAlgo{
		Name:   aeadAlgo,
		Key:    k,
		ICVLen: 128,
	}
	state.Spi = int(stateId)
	state.Reqid = stateId

	state.Src = net.ParseIP(dummyIP)
	state.Dst = net.ParseIP(dummyIP)
	return state
}

func createDummyXfrmState(state *netlink.XfrmState) error {
	state.Mark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkDecrypt,
		Mask:  linux_defaults.IPsecMarkMaskIn,
	}
	state.OutputMark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkDecrypt,
		Mask:  linux_defaults.RouteMarkMask,
	}
	return netlink.XfrmStateAdd(state)
}

// ProbeXfrmStateOutputMask probes the kernel to determine if it supports
// setting the xfrm state output mask (Linux 4.19+). It returns an error if
// the output mask is not supported or if an error occurred, nil otherwise.
func ProbeXfrmStateOutputMask() error {
	state := initDummyXfrmState()
	err := createDummyXfrmState(state)
	if err != nil {
		return err
	}
	defer netlink.XfrmStateDel(state)

	var probedState *netlink.XfrmState
	if probedState, err = netlink.XfrmStateGet(state); err != nil {
		return err
	}
	if probedState == nil || probedState.OutputMark == nil {
		return errors.New("IPSec output mark attribute missing from xfrm probe")
	}
	if probedState.OutputMark.Mask != linux_defaults.RouteMarkMask {
		return errors.New("incorrect value for probed IPSec output mask attribute")
	}
	return nil
}
