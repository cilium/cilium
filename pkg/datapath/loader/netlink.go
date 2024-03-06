// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/inctimer"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const qdiscClsact = "clsact"

func directionToParent(dir string) uint32 {
	switch dir {
	case dirIngress:
		return netlink.HANDLE_MIN_INGRESS
	case dirEgress:
		return netlink.HANDLE_MIN_EGRESS
	}
	return 0
}

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  qdiscClsact,
	}

	return netlink.QdiscReplace(qdisc)
}

type progDefinition struct {
	progName  string
	direction string
}

// replaceDatapath replaces the qdisc and BPF program for an endpoint or XDP program.
//
// When successful, returns a finalizer to allow the map cleanup operation to be
// deferred by the caller. On error, any maps pending migration are immediately
// re-pinned to their original paths and a finalizer is not returned.
//
// When replacing multiple programs from the same ELF in a loop, the finalizer
// should only be run when all the interface's programs have been replaced
// since they might share one or more tail call maps.
//
// For example, this is the case with from-netdev and to-netdev. If eth0:to-netdev
// gets its program and maps replaced and unpinned, its eth0:from-netdev counterpart
// will miss tail calls (and drop packets) until it has been replaced as well.
func replaceDatapath(ctx context.Context, ifName, objPath string, progs []progDefinition, xdpMode string) (_ func(), err error) {
	// Avoid unnecessarily loading a prog.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("getting interface %s by name: %w", ifName, err)
	}

	l := log.WithField("device", ifName).WithField("objPath", objPath).
		WithField("ifindex", link.Attrs().Index)

	// Load the ELF from disk.
	l.Debug("Loading CollectionSpec from ELF")
	spec, err := bpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("loading eBPF ELF: %w", err)
	}

	revert := func() {
		// Program replacement unsuccessful, revert bpffs migration.
		l.Debug("Reverting bpffs map migration")
		if err := bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, true); err != nil {
			l.WithError(err).Error("Failed to revert bpffs map migration")
		}
	}

	for _, prog := range progs {
		if spec.Programs[prog.progName] == nil {
			return nil, fmt.Errorf("no program %s found in eBPF ELF", prog.progName)
		}
	}

	// Unconditionally repin cilium_calls_* maps to prevent them from being
	// repopulated by the loader.
	for key, ms := range spec.Maps {
		if !strings.HasPrefix(ms.Name, "cilium_calls_") {
			continue
		}

		if err := bpf.RepinMap(bpf.TCGlobalsPath(), key, ms); err != nil {
			return nil, fmt.Errorf("repinning map %s: %w", key, err)
		}

		defer func() {
			revert := false
			// This captures named return variable err.
			if err != nil {
				revert = true
			}

			if err := bpf.FinalizeMap(bpf.TCGlobalsPath(), key, revert); err != nil {
				l.WithError(err).Error("Could not finalize map")
			}
		}()

		// Only one cilium_calls_* per collection, we can stop here.
		break
	}

	// Inserting a program into these maps will immediately cause other BPF
	// programs to call into it, even if other maps like cilium_calls haven't been
	// fully populated for the current ELF. Save their contents and avoid sending
	// them to the ELF loader.
	var policyProgs, egressPolicyProgs []ebpf.MapKV
	if pm, ok := spec.Maps[policymap.PolicyCallMapName]; ok {
		policyProgs = append(policyProgs, pm.Contents...)
		pm.Contents = nil
	}
	if pm, ok := spec.Maps[policymap.PolicyEgressCallMapName]; ok {
		egressPolicyProgs = append(egressPolicyProgs, pm.Contents...)
		pm.Contents = nil
	}

	// Load the CollectionSpec into the kernel, picking up any pinned maps from
	// bpffs in the process.
	finalize := func() {}
	pinPath := bpf.TCGlobalsPath()
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}
	if err := bpf.MkdirBPF(pinPath); err != nil {
		return nil, fmt.Errorf("creating bpffs pin path: %w", err)
	}
	l.Debug("Loading Collection into kernel")
	coll, err := bpf.LoadCollection(spec, opts)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// Temporarily rename bpffs pins of maps whose definitions have changed in
		// a new version of a datapath ELF.
		l.Debug("Starting bpffs map migration")
		if err := bpf.StartBPFFSMigration(bpf.TCGlobalsPath(), spec); err != nil {
			return nil, fmt.Errorf("Failed to start bpffs map migration: %w", err)
		}

		finalize = func() {
			l.Debug("Finalizing bpffs map migration")
			if err := bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, false); err != nil {
				l.WithError(err).Error("Could not finalize bpffs map migration")
			}
		}

		// Retry loading the Collection after starting map migration.
		l.Debug("Retrying loading Collection into kernel after map migration")
		coll, err = bpf.LoadCollection(spec, opts)
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		if _, err := fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %+v\n", err, ve); err != nil {
			return nil, fmt.Errorf("writing verifier log to stderr: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("loading eBPF collection into the kernel: %w", err)
	}
	defer coll.Close()

	// If an ELF contains one of the policy call maps, resolve and insert the
	// programs it refers to into the map. This always needs to happen _before_
	// attaching the ELF's entrypoint(s), but after the ELF's internal tail call
	// map (cilium_calls) has been populated, as doing so means the ELF's programs
	// become reachable through its policy programs, which hold references to the
	// endpoint's cilium_calls. Therefore, inserting policy programs is considered
	// an 'attachment', just not through the typical bpf hooks.
	//
	// For example, a packet can enter to-container, jump into the bpf_host policy
	// program, which then jumps into the endpoint's policy program that are
	// installed by the loops below. If we allow packets to enter the endpoint's
	// bpf programs through its tc hook(s), _all_ this plumbing needs to be done
	// first, or we risk missing tail calls.
	if len(policyProgs) != 0 {
		if err := resolveAndInsertCalls(coll, policymap.PolicyCallMapName, policyProgs); err != nil {
			revert()
			return nil, fmt.Errorf("inserting policy programs: %w", err)
		}
	}

	if len(egressPolicyProgs) != 0 {
		if err := resolveAndInsertCalls(coll, policymap.PolicyEgressCallMapName, egressPolicyProgs); err != nil {
			revert()
			return nil, fmt.Errorf("inserting egress policy programs: %w", err)
		}
	}

	// Finally, attach the endpoint's tc or xdp entry points to allow traffic to
	// flow in.
	for _, prog := range progs {
		scopedLog := l.WithField("progName", prog.progName).WithField("direction", prog.direction)
		if xdpMode != "" {
			linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), link)
			if err := bpf.MkdirBPF(linkDir); err != nil {
				return nil, fmt.Errorf("creating bpffs link dir for device %s: %w", link.Attrs().Name, err)
			}

			scopedLog.Debug("Attaching XDP program to interface")
			err = attachXDPProgram(link, coll.Programs[prog.progName], prog.progName, linkDir, xdpConfigModeToFlag(xdpMode))
		} else {
			scopedLog.Debug("Attaching TC program to interface")
			err = attachTCProgram(link, coll.Programs[prog.progName], prog.progName, directionToParent(prog.direction))
		}

		if err != nil {
			revert()
			return nil, fmt.Errorf("program %s: %w", prog.progName, err)
		}
		scopedLog.Debug("Successfully attached program to interface")
	}

	return finalize, nil
}

// resolveAndInsertCalls resolves a given slice of ebpf.MapKV containing u32 keys
// and string values (typical for a prog array) to the Programs they point to in
// the Collection. The Programs are then inserted into the Map with the given
// mapName contained within the Collection.
func resolveAndInsertCalls(coll *ebpf.Collection, mapName string, calls []ebpf.MapKV) error {
	m, ok := coll.Maps[mapName]
	if !ok {
		return fmt.Errorf("call map %s not found in Collection", mapName)
	}

	for _, v := range calls {
		name := v.Value.(string)
		slot := v.Key.(uint32)

		p, ok := coll.Programs[name]
		if !ok {
			return fmt.Errorf("program %s not found in Collection", name)
		}

		if err := m.Update(slot, p, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("inserting program %s into slot %d", name, slot)
		}

		log.Debugf("Inserted program %s into %s slot %d", name, mapName, slot)
	}

	return nil
}

// attachTCProgram attaches the TC program 'prog' to link.
func attachTCProgram(link netlink.Link, prog *ebpf.Program, progName string, qdiscParent uint32) error {
	if prog == nil {
		return errors.New("cannot attach a nil program")
	}

	if err := replaceQdisc(link); err != nil {
		return fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    qdiscParent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  option.Config.TCFilterPriority,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, link.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replacing tc filter for interface %s: %w", link.Attrs().Name, err)
	}

	return nil
}

// removeTCFilters removes all tc filters from the given interface.
// Direction is passed as netlink.HANDLE_MIN_{INGRESS,EGRESS} via tcDir.
func removeTCFilters(ifName string, tcDir uint32) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	filters, err := netlink.FilterList(link, tcDir)
	if err != nil {
		return err
	}

	for _, f := range filters {
		if err := netlink.FilterDel(f); err != nil {
			return err
		}
	}

	return nil
}

// reloadIPSecOnLinkChanges subscribes to link changes to detect newly added devices
// and reinitializes IPsec on changes. Only in effect for ENI mode in which we expect
// new devices at runtime.
func (l *loader) reloadIPSecOnLinkChanges() {
	// settleDuration is the amount of time to wait for further link updates
	// before proceeding with reinitialization. This avoids back-to-back
	// reinitialization when multiple link changes are made at once.
	const settleDuration = 1 * time.Second

	if !option.Config.EnableIPSec || option.Config.IPAM != ipamOption.IPAMENI {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	updates := make(chan netlink.LinkUpdate)

	if err := netlink.LinkSubscribe(updates, ctx.Done()); err != nil {
		log.WithError(err).Fatal("Failed to subscribe for link changes")
	}

	go func() {
		defer cancel()

		timer, stop := inctimer.New()
		defer stop()

		// If updates arrive during settle duration a single element
		// is sent to this channel and we reinitialize right away
		// without waiting for further updates.
		trigger := make(chan struct{}, 1)

		for {
			// Wait for first update or trigger before reinitializing.
		getUpdate:
			select {
			case u, ok := <-updates:
				if !ok {
					return
				}
				// Ignore veth devices
				if u.Type() == "veth" {
					goto getUpdate
				}
			case <-trigger:
			}

			log.Info("Reinitializing IPsec due to device changes")
			err := l.reinitializeIPSec(ctx)
			if err != nil {
				// We may fail if links have been removed during the reload. In this case
				// the updates channel will have queued updates which will retrigger the
				// reinitialization.
				log.WithError(err).Warn("Failed to reinitialize IPsec after device change")
			}

			// Avoid reinitializing repeatedly in short period of time
			// by draining further updates for 'settleDuration'.
			settled := timer.After(settleDuration)
		settleLoop:
			for {
				select {
				case <-settled:
					break settleLoop
				case u := <-updates:
					// Ignore veth devices
					if u.Type() == "veth" {
						continue
					}

					// Trigger reinit immediately after
					// settle duration has passed.
					select {
					case trigger <- struct{}{}:
					default:
					}
				}

			}
		}
	}()
}

// DeviceHasTCProgramLoaded checks whether a given device has tc filter/qdisc progs attached.
func (l *loader) DeviceHasTCProgramLoaded(hostInterface string, checkEgress bool) (bool, error) {
	const bpfProgPrefix = "cil_"

	link, err := netlink.LinkByName(hostInterface)
	if err != nil {
		return false, fmt.Errorf("unable to find endpoint link by name: %w", err)
	}

	dd, err := netlink.QdiscList(link)
	if err != nil {
		return false, fmt.Errorf("unable to fetch qdisc list for endpoint: %w", err)
	}
	var found bool
	for _, d := range dd {
		if d.Type() == qdiscClsact {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}

	ff, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, fmt.Errorf("unable to fetch ingress filter list: %w", err)
	}
	var filtersCount int
	for _, f := range ff {
		if filter, ok := f.(*netlink.BpfFilter); ok {
			if strings.HasPrefix(filter.Name, bpfProgPrefix) {
				filtersCount++
			}
		}
	}
	if filtersCount == 0 {
		return false, nil
	}
	if !checkEgress {
		return true, nil
	}

	ff, err = netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return false, fmt.Errorf("unable to fetch egress filter list: %w", err)
	}
	filtersCount = 0
	for _, f := range ff {
		if filter, ok := f.(*netlink.BpfFilter); ok {
			if strings.HasPrefix(filter.Name, bpfProgPrefix) {
				filtersCount++
			}
		}
	}
	return len(ff) > 0 && filtersCount > 0, nil
}
