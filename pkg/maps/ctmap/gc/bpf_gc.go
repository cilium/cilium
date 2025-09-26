package gc

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	bpfgen "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/cell"
)

type ctmapGCScanner struct {
	progs *bpfgen.CTMapGCMarkPrograms
}

func newCTMapGCScanner(logger *slog.Logger, lc cell.Lifecycle) (*ctmapGCScanner, error) {
	ct4MarkMap := ctmap.GCMarkMap()
	if err := ct4MarkMap.OpenOrCreate(); err != nil {
		return nil, err
	}

	progs, err := loader.LoadCTMapGCPass(logger, &ct4MarkMap.Map)
	if err != nil {
		return nil, err
	}

	m := ctmap.Maps(true, false)[0]
	if err := m.OpenOrCreate(); err != nil {
		return nil, fmt.Errorf("Failed to open map: %w", err)
	}

	sweepProgs, err := loader.LoadCTMapGCSweep(logger, &m.Map)
	if err != nil {
		return nil, err
	}

	lc.Append(cell.Hook{OnStart: func(hc cell.HookContext) error {
		for {
			time.Sleep(time.Second * 60)

			iter, err := link.AttachIter(link.IterOptions{
				Program: progs.IterateCt,
				Map:     m.GetMap(),
			})
			if err != nil {
				return fmt.Errorf("creating iterator: %w", err)
			}

			rc, err := iter.Open()
			if err != nil {
				return fmt.Errorf("creating reader: %w", err)
			}

			_, err = io.ReadAll(rc)
			if err != nil {
				return err
			}

			rc.Close()
			iter.Close()

			iter, err = link.AttachIter(link.IterOptions{
				Program: sweepProgs.IterateCt,
				Map:     ct4MarkMap.GetMap(),
			})
			if err != nil {
				return fmt.Errorf("creating iterator: %w", err)
			}
			rc, err = iter.Open()
			if err != nil {
				return fmt.Errorf("creating reader: %w", err)
			}

			_, err = io.ReadAll(rc)
			if err != nil {
				return fmt.Errorf("failed to read: %w", err)
			}
			rc.Close()
			iter.Close()

			if err := ct4MarkMap.DeleteAll(); err != nil {
				return fmt.Errorf("failed to truncate map: %w", err)
			}
		}
	}})

	return &ctmapGCScanner{
		progs: progs,
	}, nil
}
