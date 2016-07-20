package daemon

import (
	"os"
	"strconv"
	"time"

	"github.com/noironetworks/cilium-net/bpf/ctmap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/bpf"
	"github.com/noironetworks/cilium-net/common/types"
)

const (
	GcInterval int = 10
)

func runGC(e *types.Endpoint, prefix string, ctType ctmap.CtType) {
	file := prefix + strconv.Itoa(int(e.ID))
	fd, err := bpf.ObjGet(file)
	if err != nil {
		log.Warningf("Unable to open CT map %s: %s\n", file, err)
		return
	}

	f := os.NewFile(uintptr(fd), file)
	m := ctmap.CtMap{Fd: fd, Type: ctType}

	deleted := m.GC(uint16(GcInterval))
	if deleted > 0 {
		log.Debugf("Deleted %d entries from map %s", deleted, file)
	}

	f.Close()
}

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

				runGC(e, common.BPFMapCT6, ctmap.CtTypeIPv6)
				runGC(e, common.BPFMapCT4, ctmap.CtTypeIPv4)
			}

			d.endpointsMU.Unlock()
			time.Sleep(sleepTime)
		}
	}()
}
