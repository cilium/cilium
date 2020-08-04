// Copyright 2020 Authors of Cilium
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

package bandwidth

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	Subsystem = "bandwidth-manager"

	MapName = "cilium_throttle"
	// Flow aggregate is per Pod, so same size as Endpoint map.
	MapSize = lxcmap.MaxEntries

	// EgressBandwidth is the K8s Pod annotation.
	EgressBandwidth = "kubernetes.io/egress-bandwidth"

	DefaultTimeHorizon = 2000 * 1000 * 1000
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, Subsystem)

type EdtId struct {
	Id uint64 `align:"id"`
}

func (k *EdtId) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *EdtId) NewValue() bpf.MapValue     { return &EdtInfo{} }
func (k *EdtId) String() string             { return fmt.Sprintf("%s", k.Id) }
func (k *EdtId) DeepCopyMapKey() bpf.MapKey { return &EdtId{k.Id} }

type EdtInfo struct {
	Bps             uint64    `align:"bps"`
	TimeLast        uint64    `align:"t_last"`
	TimeHorizonDrop uint64    `align:"t_horizon_drop"`
	Pad             [4]uint64 `align:"pad"`
}

func (v *EdtInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *EdtInfo) String() string              { return fmt.Sprintf("%v", v.Bps) }
func (v *EdtInfo) DeepCopyMapValue() bpf.MapValue {
	return &EdtInfo{v.Bps, v.TimeLast, v.TimeHorizonDrop, v.Pad}
}

var ThrottleMap = bpf.NewMap(
	MapName,
	bpf.MapTypeHash,
	&EdtId{}, int(unsafe.Sizeof(EdtId{})),
	&EdtInfo{}, int(unsafe.Sizeof(EdtInfo{})),
	MapSize,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()

type ThrottleBPFMap struct{}

func (*ThrottleBPFMap) Update(Id uint16, Bps uint64) error {
	return ThrottleMap.Update(
		&EdtId{Id: uint64(Id)},
		&EdtInfo{Bps: Bps, TimeHorizonDrop: uint64(DefaultTimeHorizon)})
}

func (*ThrottleBPFMap) Delete(Id uint16) error {
	return ThrottleMap.Delete(
		&EdtId{Id: uint64(Id)})
}

func GetBytesPerSec(bandwidth string) (uint64, error) {
	res, err := resource.ParseQuantity(bandwidth)
	if err != nil {
		return 0, err
	}
	return uint64(res.Value() / 8), err
}

func InitBandwidthManager() {
	if option.Config.DryMode || !option.Config.EnableBandwidthManager {
		return
	}
	if len(option.Config.Devices) == 0 {
		log.Warn("BPF bandwidth manager could not detect host devices. Disabling the feature.")
		option.Config.EnableBandwidthManager = false
		return
	}

	kernelGood := false
	if h := probes.NewProbeManager().GetHelpers("sched_act"); h != nil {
		// We at least need 5.0 kernel for native TCP EDT integration, but below
		// helper is only for 5.1 kernels and onwards.
		if _, ok := h["bpf_skb_ecn_set_ce"]; ok {
			kernelGood = true
		}
	}
	if !kernelGood {
		log.Warn("BPF bandwidth manager needs kernel 5.1.0 or newer. Disabling the feature.")
		option.Config.EnableBandwidthManager = false
		return
	}

	log.Infof("Setting up BPF bandwidth manager")
	if _, err := ThrottleMap.OpenOrCreate(); err != nil {
		log.WithError(err).Fatal("Failed to access ThrottleMap")
	}

	type setting struct {
		name string
		val  string
	}
	baseSettings := []setting{
		{"net.core.netdev_max_backlog", "1000"},
		{"net.core.somaxconn", "4096"},
		{"net.core.default_qdisc", "fq"},
		{"net.ipv4.tcp_congestion_control", "bbr"},
		{"net.ipv4.tcp_max_syn_backlog", "4096"},
	}
	for _, s := range baseSettings {
		log.Infof("Setting sysctl %s=%s", s.name, s.val)
		if err := sysctl.Write(s.name, s.val); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.SysParamName:  s.name,
				logfields.SysParamValue: s.val,
			}).Fatal("Failed to sysctl -w")
		}
	}

	for _, device := range option.Config.Devices {
		link, err := netlink.LinkByName(device)
		if err != nil {
			log.WithError(err).WithField("device", device).Warn("Link does not exist")
			continue
		}
		// We strictly want to avoid an down/up cycle on the device at
		// runtime, so given we've changed the default qdisc to FQ, we
		// need to reset the root qdisc, and then set up MQ which will
		// automatically get FQ leaf qdiscs (given it's been default).
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_ROOT,
			},
			QdiscType: "noqueue",
		}
		if err := netlink.QdiscReplace(qdisc); err != nil {
			log.WithError(err).WithField("device", device).
				Fatalf("Cannot replace root Qdisc to %s", qdisc.QdiscType)
		}
		qdisc = &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_ROOT,
			},
			QdiscType: "mq",
		}
		which := "mq with fq leafs"
		if err := netlink.QdiscReplace(qdisc); err != nil {
			// No MQ support, so just replace to FQ directly.
			fq := &netlink.Fq{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: link.Attrs().Index,
					Parent:    netlink.HANDLE_ROOT,
				},
				Pacing: 1,
			}
			// At this point there is nothing we can do about
			// it if we fail here, so hard bail out.
			if err = netlink.QdiscReplace(fq); err != nil {
				log.WithError(err).WithField("device", device).
					Fatalf("Cannot replace root Qdisc to %s", fq.Type())
			}
			which = "fq"
		}
		log.WithField("device", device).Infof("Setting qdisc to %s", which)
	}
}
