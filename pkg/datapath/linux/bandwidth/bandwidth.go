// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// NOTE: We can only build on linux because we import bwmap which in turn imports pkg/ebpf and pkg/bpf
//       which throw build errors when building on non-linux platforms.

package bandwidth

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// EgressBandwidth is the K8s Pod annotation.
	EgressBandwidth = "kubernetes.io/egress-bandwidth"
	// IngressBandwidth is the K8s Pod annotation.
	IngressBandwidth = "kubernetes.io/ingress-bandwidth"

	EnableBBR = "enable-bbr"
)

type manager struct {
	resetQueues, enabled bool

	params   bandwidthManagerParams
	jobGroup job.Group
}

func (m *manager) Enabled() bool {
	return m.enabled
}

func (m *manager) BBREnabled() bool {
	return m.params.Config.EnableBBR
}

func (m *manager) defines() (defines.Map, error) {
	cDefinesMap := make(defines.Map)
	if m.resetQueues {
		cDefinesMap["RESET_QUEUES"] = "1"
	}

	if m.Enabled() {
		cDefinesMap["ENABLE_BANDWIDTH_MANAGER"] = "1"
		cDefinesMap["THROTTLE_MAP"] = bwmap.MapName
		cDefinesMap["THROTTLE_MAP_SIZE"] = fmt.Sprintf("%d", bwmap.MapSize)
	}

	return cDefinesMap, nil
}

func (m *manager) DeleteEndpointBandwidthLimit(epID uint16) error {
	if m.enabled {
		return bwmap.Delete(epID)
	}
	return nil
}

func GetBytesPerSec(bandwidth string) (uint64, error) {
	res, err := resource.ParseQuantity(bandwidth)
	if err != nil {
		return 0, err
	}
	return uint64(res.Value() / 8), err
}

// probe checks the various system requirements of the bandwidth manager and disables it if they are
// not met.
func (m *manager) probe() error {
	// We at least need 5.1 kernel for native TCP EDT integration
	// and writable queue_mapping that we use. Below helper is
	// available for 5.1 kernels and onwards.
	kernelGood := probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbEcnSetCe) == nil
	m.resetQueues = kernelGood
	if !m.params.Config.EnableBandwidthManager {
		return nil
	}
	if _, err := sysctl.Read("net.core.default_qdisc"); err != nil {
		m.params.Log.WithError(err).Warn("BPF bandwidth manager could not read procfs. Disabling the feature.")
		return nil
	}
	if !kernelGood {
		m.params.Log.Warn("BPF bandwidth manager needs kernel 5.1 or newer. Disabling the feature.")
		return nil
	}
	if m.params.Config.EnableBBR {
		// We at least need 5.18 kernel for Pod-based BBR TCP congestion
		// control since earlier kernels just clear the skb->tstamp upon
		// netns traversal. See also:
		//
		// - https://lpc.events/event/11/contributions/953/
		// - https://lore.kernel.org/bpf/20220302195519.3479274-1-kafai@fb.com/
		if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbSetTstamp) != nil {
			return fmt.Errorf("cannot enable --%s, needs kernel 5.18 or newer", EnableBBR)
		}
	}

	// Going via host stack will orphan skb->sk, so we do need BPF host
	// routing for it to work properly.
	if m.params.Config.EnableBBR && m.params.DaemonConfig.EnableHostLegacyRouting {
		return fmt.Errorf("BPF bandwidth manager's BBR setup requires BPF host routing.")
	}

	if m.params.Config.EnableBandwidthManager && m.params.DaemonConfig.EnableIPSec {
		m.params.Log.Warning("The bandwidth manager cannot be used with IPSec. Disabling the bandwidth manager.")
		return nil
	}

	m.enabled = true
	return nil
}

func (m *manager) run(ctx context.Context, health cell.HealthReporter) error {
	m.params.Log.Info("Setting up BPF bandwidth manager")

	if err := bwmap.ThrottleMap().OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to access ThrottleMap: %w", err)
	}

	if err := setBaselineSysctls(m.params); err != nil {
		return fmt.Errorf("failed to set sysctl needed by BPF bandwidth manager: %w", err)
	}

	txn := m.params.DB.WriteTxn(m.params.Devices)
	defer txn.Abort()

	tracker, err := m.params.Devices.DeleteTracker(txn, "bandwidth-manager")
	if err != nil {
		return fmt.Errorf("failed to create device tracker: %w", err)
	}
	txn.Commit()
	defer tracker.Close()

	// Map of devices that failed to reconcile.
	badDevices := make(map[int]error)
	retryTicker := time.NewTicker(1 * time.Minute)
	defer retryTicker.Stop()

	minRev := uint64(0)
	var invalid <-chan struct{}
	for {
		// Process all changes since minRev. On startup we process all entries in the table, afterwards changes.
		rxn := m.params.DB.ReadTxn()
		minRev, invalid, err = tracker.Process(rxn, minRev, func(device *tables.Device, deleted bool, rev uint64) error {
			// Ignore non-selected device changes and deleted devices.
			if !device.Selected || deleted {
				delete(badDevices, device.Index)
				return nil
			}

			if err := m.reconcileQdiscsForDevice(device); err != nil {
				m.params.Log.WithError(err).WithField("device", device).Warn("Failed to reconcile qdiscs for device")
				badDevices[device.Index] = err
			} else {
				badDevices[device.Index] = nil
			}

			return nil
		})
		if err != nil {
			health.Degraded("Failed to process device updates", err)
			continue
		}

		updateHealthStatus(badDevices, health)

		select {
		case <-ctx.Done():
			return nil

		case <-invalid:
			continue

		case <-retryTicker.C:
			for idx, err := range badDevices {
				if err == nil {
					continue
				}

				device, _, found := m.params.Devices.First(rxn, tables.DeviceIDIndex.Query(idx))
				if !found {
					delete(badDevices, idx)
					continue
				}

				if err := m.reconcileQdiscsForDevice(device); err != nil {
					m.params.Log.WithError(err).WithField("device", device).Warn("Failed to reconcile qdiscs for device")
					badDevices[device.Index] = err
				} else {
					badDevices[device.Index] = nil
				}
			}
		}
	}
}

func updateHealthStatus(badDevices map[int]error, health cell.HealthReporter) {
	ok := 0
	var errs error
	for _, v := range badDevices {
		if v == nil {
			ok++
		} else {
			errs = errors.Join(errs, v)
		}
	}
	if ok == len(badDevices) {
		health.OK(fmt.Sprintf("OK (%d/%d)", ok, len(badDevices)))
	} else {
		health.Degraded(fmt.Sprintf("Degraded (%d/%d)", ok, len(badDevices)), errs)
	}
}

func (m *manager) reconcileQdiscsForDevice(device *tables.Device) error {
	link, err := netlink.LinkByIndex(device.Index)
	if err != nil {
		return fmt.Errorf("Link for device idx '%d' does not exist", device.Index)
	}

	// Get the current qdiscs on the device.
	curQdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("cannot list qdiscs on device %s: %w", device.Name, err)
	}
	for _, qdisc := range curQdiscs {
		if qdisc.Attrs().Parent == netlink.HANDLE_ROOT && qdisc.Type() == "mq" {
			return nil
		}
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
		return fmt.Errorf("cannot replace root Qdisc to %s on device %s: %w", qdisc.QdiscType, device.Name, err)
	}

	qdisc = &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_ROOT,
		},
		QdiscType: "mq",
	}
	which := "mq with fq leaves"
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
			return fmt.Errorf("cannot replace root Qdisc to %s on device %s: %w", fq.Type(), device.Name, err)
		}
		which = "fq"
	}

	m.params.Log.WithField("device", device).Infof("Setting qdisc to %s", which)
	return nil
}

func setBaselineSysctls(p bandwidthManagerParams) error {
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

		scopedLog := p.Log.WithFields(logrus.Fields{
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
	if p.Config.EnableBBR {
		congctl = "bbr"
	}

	baseStringSettings := map[string]string{
		"net.core.default_qdisc":          "fq",
		"net.ipv4.tcp_congestion_control": congctl,
	}

	for name, value := range baseStringSettings {
		p.Log.WithFields(logrus.Fields{
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
	if p.Config.EnableBBR {
		for name, value := range extraSettings {
			p.Log.WithFields(logrus.Fields{
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
