// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// NOTE: We can only build on linux because we import bwmap which in turn imports pkg/ebpf and pkg/bpf
//       which throw build errors when building on non-linux platforms.

package bandwidth

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/bwmap"
)

const (
	// EgressBandwidth is the K8s Pod annotation.
	EgressBandwidth = "kubernetes.io/egress-bandwidth"
	// IngressBandwidth is the K8s Pod annotation.
	IngressBandwidth = "kubernetes.io/ingress-bandwidth"

	// FqDefaultHorizon represents maximum allowed departure
	// time delta in future. Given applications can set SO_TXTIME
	// from user space this is a limit to prevent buggy applications
	// to fill the FQ qdisc.
	FqDefaultHorizon = bwmap.DefaultDropHorizon
	// FqDefaultBuckets is the default 32k (2^15) bucket limit for bwm.
	// Too low bucket limit can cause scalability issue.
	FqDefaultBuckets = 15
)

type manager struct {
	resetQueues, enabled bool

	params bandwidthManagerParams
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

func (m *manager) UpdateBandwidthLimit(epID uint16, bytesPerSecond uint64) {
	if m.enabled {
		txn := m.params.DB.WriteTxn(m.params.EdtTable)
		m.params.EdtTable.Insert(
			txn,
			bwmap.NewEdt(epID, bytesPerSecond),
		)
		txn.Commit()
	}
}

func (m *manager) DeleteBandwidthLimit(epID uint16) {
	if m.enabled {
		txn := m.params.DB.WriteTxn(m.params.EdtTable)
		obj, _, found := m.params.EdtTable.Get(txn, bwmap.EdtIDIndex.Query(epID))
		if found {
			m.params.EdtTable.Delete(txn, obj)
		}
		txn.Commit()
	}
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
	if _, err := m.params.Sysctl.Read([]string{"net", "core", "default_qdisc"}); err != nil {
		m.params.Log.Warn("BPF bandwidth manager could not read procfs. Disabling the feature.", logfields.Error, err)
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
			return fmt.Errorf("cannot enable --%s, needs kernel 5.18 or newer", types.EnableBBRFlag)
		}
	}

	// Going via host stack will orphan skb->sk, so we do need BPF host
	// routing for it to work properly.
	if m.params.Config.EnableBBR && m.params.DaemonConfig.EnableHostLegacyRouting {
		return fmt.Errorf("BPF bandwidth manager's BBR setup requires BPF host routing.")
	}

	if m.params.Config.EnableBandwidthManager && m.params.DaemonConfig.EnableIPSec {
		m.params.Log.Warn("The bandwidth manager cannot be used with IPSec. Disabling the bandwidth manager.")
		return nil
	}

	m.enabled = true
	return nil
}

func (m *manager) init() error {
	m.params.Log.Info("Setting up BPF bandwidth manager")

	if err := bwmap.ThrottleMap().OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to access ThrottleMap: %w", err)
	}

	if err := setBaselineSysctls(m.params); err != nil {
		return fmt.Errorf("failed to set sysctl needed by BPF bandwidth manager: %w", err)
	}
	return nil
}

func setBaselineSysctls(p bandwidthManagerParams) error {
	// Ensure interger type sysctls are no smaller than our baseline settings
	baseIntSettings := []struct {
		name []string
		val  int64
	}{
		{[]string{"net", "core", "netdev_max_backlog"}, 1000},
		{[]string{"net", "core", "somaxconn"}, 4096},
		{[]string{"net", "ipv4", "tcp_max_syn_backlog"}, 4096},
	}

	for _, setting := range baseIntSettings {
		currentValue, err := p.Sysctl.ReadInt(setting.name)
		if err != nil {
			return fmt.Errorf("read sysctl %s failed: %w", strings.Join(setting.name, "."), err)
		}

		scopedLog := p.Log.With(
			logfields.SysParamName, strings.Join(setting.name, "."),
			logfields.SysParamValue, currentValue,
			"baselineValue", setting.val,
		)

		if currentValue >= setting.val {
			scopedLog.Info("Skip setting sysctl as it already meets baseline")
			continue
		}

		scopedLog.Info("Setting sysctl to baseline for BPF bandwidth manager")
		if err := p.Sysctl.WriteInt(setting.name, setting.val); err != nil {
			return fmt.Errorf("set sysctl %s=%d failed: %w", strings.Join(setting.name, "."), setting.val, err)
		}
	}

	// Ensure string type sysctls
	congctl := "cubic"
	if p.Config.EnableBBR {
		congctl = "bbr"
	}

	sysctls := []tables.Sysctl{
		{Name: []string{"net", "core", "default_qdisc"}, Val: "fq"},
		{Name: []string{"net", "ipv4", "tcp_congestion_control"}, Val: congctl},
	}

	// Few extra knobs which can be turned on along with pacing. EnableBBR
	// also provides the right kernel dependency implicitly as well.
	if p.Config.EnableBBR {
		sysctls = append(sysctls, tables.Sysctl{
			Name: []string{"net", "ipv4", "tcp_slow_start_after_idle"}, Val: "0",
		})
	}

	if err := p.Sysctl.ApplySettings(sysctls); err != nil {
		return fmt.Errorf("failed to apply sysctls: %w", err)
	}

	return nil
}
