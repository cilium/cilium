package loader

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
	bpfgen "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

const markMapKey = "ct4_purge3"

// TODO: can all be in the same file...
func LoadCTMapGCSweep(l *slog.Logger, ct4GlobalMap *bpf.Map) (*bpfgen.CTMapGCSweepPrograms, error) {
	spec, err := bpfgen.LoadCTMapGCSweep()
	if err != nil {
		return nil, fmt.Errorf("load eBPF ELF: %w", err)
	}

	mapReplacements := make(map[string]*bpf.Map)

	if m := spec.Maps["cilium_ct_any4_global"]; m == nil {
		return nil, fmt.Errorf("cilium_ct_any4_global map not found in spec")
	} else if ct4GlobalMap == nil {
		return nil, fmt.Errorf("nil map")
	} else {
		m.Flags = ct4GlobalMap.Flags()
		m.MaxEntries = ct4GlobalMap.MaxEntries()
		mapReplacements["cilium_ct_any4_global"] = ct4GlobalMap
	}

	// Since the programs use the bpf_sock_destroy() kfunc, the loader
	// parses and caches BTF from vmlinux on the first go to be reused
	// by subsequent program loads. For now, only bpf_sock_term uses kfuncs,
	// and we only load this at the start, so flush this cache after loading
	// is done to avoid holding onto an extra ~15MB of memory.
	//
	// See GH-37907 for discussion
	defer btf.FlushKernelSpec()

	// We can't assign directly to a sock_termObjects, since some maps and
	// programs may be missing.
	coll, commit, err := bpf.LoadCollection(l, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		MapReplacements: mapReplacements,
	})

	if err != nil {
		return nil, fmt.Errorf("loading collection: %w", err)
	}

	if err := commit(); err != nil {
		return nil, fmt.Errorf("committing bpf pins: %w", err)
	}

	return &bpfgen.CTMapGCSweepPrograms{
		IterateCt: coll.Programs["iterate_ct"],
	}, nil
}

func LoadCTMapGCPass(l *slog.Logger, ct4MarkedMap *bpf.Map) (*bpfgen.CTMapGCMarkPrograms, error) {
	spec, err := bpfgen.LoadCTMapGCMark()
	if err != nil {
		return nil, fmt.Errorf("load eBPF ELF: %w", err)
	}

	mapReplacements := make(map[string]*bpf.Map)

	if m := spec.Maps[markMapKey]; m == nil {
		return nil, fmt.Errorf("%s map not found in spec", markMapKey)
	} else if ct4MarkedMap == nil {
		return nil, fmt.Errorf("nil map")
	} else {
		m.Flags = ct4MarkedMap.Flags()
		m.MaxEntries = ct4MarkedMap.MaxEntries()
		mapReplacements[markMapKey] = ct4MarkedMap
	}

	// Since the programs use the bpf_sock_destroy() kfunc, the loader
	// parses and caches BTF from vmlinux on the first go to be reused
	// by subsequent program loads. For now, only bpf_sock_term uses kfuncs,
	// and we only load this at the start, so flush this cache after loading
	// is done to avoid holding onto an extra ~15MB of memory.
	//
	// See GH-37907 for discussion
	defer btf.FlushKernelSpec()

	// We can't assign directly to a sock_termObjects, since some maps and
	// programs may be missing.
	coll, commit, err := bpf.LoadCollection(l, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		MapReplacements: mapReplacements,
	})

	if err != nil {
		return nil, fmt.Errorf("loading collection: %w", err)
	}

	if err := commit(); err != nil {
		return nil, fmt.Errorf("committing bpf pins: %w", err)
	}

	return &bpfgen.CTMapGCMarkPrograms{
		IterateCt: coll.Programs["iterate_ct"],
	}, nil
}
