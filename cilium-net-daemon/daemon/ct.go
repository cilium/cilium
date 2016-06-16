package daemon

import (
	"os"
	"time"

	"github.com/noironetworks/cilium-net/bpf/ctmap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/bpf"
)

const (
	GcInterval int = 10
)

func (d *Daemon) EnableConntrackGC() {
	go func() {
		for {
			sleepTime := time.Duration(GcInterval) * time.Second

			d.endpointsMU.Lock()

			for k, _ := range d.endpoints {
				e := d.endpoints[k]
				if e.Consumable == nil {
					continue
				}

				file := common.BPFMapCT + e.ID
				fd, err := bpf.ObjGet(file)
				if err != nil {
					log.Warningf("Unable to open CT map %s: %s\n", file, err)
					continue
				}

				f := os.NewFile(uintptr(fd), file)
				m := ctmap.CtMap{Fd: fd}

				deleted := m.GC(uint16(GcInterval))
				if deleted > 0 {
					log.Debugf("Deleted %d entries from map %s", deleted, file)
				}

				f.Close()
			}

			d.endpointsMU.Unlock()
			time.Sleep(sleepTime)
		}
	}()
}
