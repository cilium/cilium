// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
)

const (
	subsystem = "bandwidth-manager"

	// EgressBandwidth is the K8s Pod annotation.
	EgressBandwidth = "kubernetes.io/egress-bandwidth"
	// IngressBandwidth is the K8s Pod annotation.
	IngressBandwidth = "kubernetes.io/ingress-bandwidth"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

func GetBytesPerSec(bandwidth string) (uint64, error) {
	res, err := resource.ParseQuantity(bandwidth)
	if err != nil {
		return 0, err
	}
	return uint64(res.Value() / 8), err
}

func ProbeBandwidthManager() {
	if option.Config.DryMode {
		return
	}

	// We at least need 5.1 kernel for native TCP EDT integration
	// and writable queue_mapping that we use. Below helper is
	// available for 5.1 kernels and onwards.
	kernelGood := probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbEcnSetCe) == nil
	option.Config.ResetQueueMapping = kernelGood
	if !option.Config.EnableBandwidthManager {
		return
	}
	if _, err := sysctl.Read("net.core.default_qdisc"); err != nil {
		log.WithError(err).Warn("BPF bandwidth manager could not read procfs. Disabling the feature.")
		option.Config.EnableBandwidthManager = false
		return
	}
	if !kernelGood {
		log.Warn("BPF bandwidth manager needs kernel 5.1 or newer. Disabling the feature.")
		option.Config.EnableBandwidthManager = false
		return
	}
	if option.Config.EnableBBR {
		// We at least need 5.18 kernel for Pod-based BBR TCP congestion
		// control since earlier kernels just clear the skb->tstamp upon
		// netns traversal. See also:
		//
		// - https://lpc.events/event/11/contributions/953/
		// - https://lore.kernel.org/bpf/20220302195519.3479274-1-kafai@fb.com/
		if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbSetTstamp) != nil {
			log.Fatalf("Cannot enable --%s, needs kernel 5.18 or newer.",
				option.EnableBBR)
		}
	}
}

func setBaselineSysctls() error {
	// Ensure interger type sysctls are no smaller than our baseline settings
	baseIntSettings := map[string]int64{
		"net.core.netdev_max_backlog":  1000,
		"net.core.somaxconn":           4096,
		"net.ipv4.tcp_max_syn_backlog": 4096,
	}

	for name, value := range baseIntSettings {
		currentValue, err := sysctl.ReadInt(name)
		if err != nil {
			return fmt.Errorf("read sysctl %s failed: %s", name, err)
		}

		scopedLog := log.WithFields(logrus.Fields{
			logfields.SysParamName:  name,
			logfields.SysParamValue: currentValue,
			"baselineValue":         value,
		})

		if currentValue >= value {
			scopedLog.Info("Skip setting sysctl as it already meets baseline")
			continue
		}

		scopedLog.Info("Setting sysctl to baseline for BPF bandwidth manager")
		if err := sysctl.WriteInt(name, value); err != nil {
			return fmt.Errorf("set sysctl %s=%d failed: %s", name, value, err)
		}
	}

	// Ensure string type sysctls
	congctl := "cubic"
	if option.Config.EnableBBR {
		congctl = "bbr"
	}

	baseStringSettings := map[string]string{
		"net.core.default_qdisc":          "fq",
		"net.ipv4.tcp_congestion_control": congctl,
	}

	for name, value := range baseStringSettings {
		log.WithFields(logrus.Fields{
			logfields.SysParamName: name,
			"baselineValue":        value,
		}).Info("Setting sysctl to baseline for BPF bandwidth manager")

		if err := sysctl.Write(name, value); err != nil {
			return fmt.Errorf("set sysctl %s=%s failed: %s", name, value, err)
		}
	}

	// Extra settings
	extraSettings := map[string]int64{
		"net.ipv4.tcp_slow_start_after_idle": 0,
	}

	// Few extra knobs which can be turned on along with pacing. EnableBBR
	// also provides the right kernel dependency implicitly as well.
	if option.Config.EnableBBR {
		for name, value := range extraSettings {
			log.WithFields(logrus.Fields{
				logfields.SysParamName: name,
				"baselineValue":        value,
			}).Info("Setting sysctl to baseline for BPF bandwidth manager")

			if err := sysctl.WriteInt(name, value); err != nil {
				return fmt.Errorf("set sysctl %s=%d failed: %s", name, value, err)
			}
		}
	}

	return nil
}

func InitBandwidthManager() {
	if option.Config.DryMode || !option.Config.EnableBandwidthManager {
		return
	}

	if len(option.Config.GetDevices()) == 0 {
		log.Warn("BPF bandwidth manager could not detect host devices. Disabling the feature.")
		option.Config.EnableBandwidthManager = false
		return
	}
	// Going via host stack will orphan skb->sk, so we do need BPF host
	// routing for it to work properly.
	if option.Config.EnableBBR && option.Config.EnableHostLegacyRouting {
		log.Fatal("BPF bandwidth manager's BBR setup requires BPF host routing.")
	}

	log.Info("Setting up BPF bandwidth manager")

	if err := bwmap.ThrottleMap().OpenOrCreate(); err != nil {
		log.WithError(err).Fatal("Failed to access ThrottleMap")
	}

	if err := setBaselineSysctls(); err != nil {
		log.WithError(err).Fatal("Failed to set sysctl needed by BPF bandwidth manager.")
	}

	for _, device := range option.Config.GetDevices() {
		link, err := netlink.LinkByName(device)
		if err != nil {
			log.WithError(err).WithField("device", device).Warn("Link does not exist")
			continue
		}
		// We strictly want to avoid a down/up cycle on the device at
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
