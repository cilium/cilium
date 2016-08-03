package daemon

/*
#cgo CFLAGS: -I../../bpf/include
#include <linux/perf_event.h>
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/noironetworks/cilium-net/common/bpf"
	"github.com/noironetworks/cilium-net/common/types"
)

func (d *Daemon) receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	data := msg.DataDirect()
	if data[0] == bpf.CILIUM_NOTIFY_DROP {
		dn := bpf.DropNotify{}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &dn); err != nil {
			log.Warningf("Error while parsing drop notification message: %s\n", err)
			return
		}
		d.endpointsLearningMU.RLock()
		for _, v := range d.endpointsLearning {
			if dn.DstID == uint32(v.EndpointID) {
				go func(epID uint16, lblID uint32) {
					sec, err := d.GetLabels(lblID)
					if err != nil {
						log.Errorf("Error while getting label ID %d: %s", lblID, err)
						return
					}
					if sec == nil {
						log.Warningf("Endpoint %d is receiving traffic from an unknown label ID %d", epID, lblID)
						return
					}
					if err := d.EndpointLabelsUpdate(epID, types.LabelOp{types.AddLabelsOp: sec.Labels}); err != nil {
						log.Warningf("Error while add learned labels into the daemon %s", err)
					}
				}(v.EndpointID, dn.SrcLabel)
			}
		}
		d.endpointsLearningMU.RUnlock()
	}
}

func (d *Daemon) lostEvent(msg *bpf.PerfEventLost, cpu int) {
}

func (d *Daemon) EnableLearningTraffic() {
	startChan := make(chan bool, 1)
	stopChan1 := make(chan bool, 1)
	eventStopped := make(chan bool, 1)

	go func() {
		for {
			select {
			case lEP := <-d.endpointsLearningRegister:
				log.Debugf("Registering endpoint %+v", lEP)
				d.endpointsLearningMU.Lock()
				if lEP.Learn {
					if len(d.endpointsLearning) == 0 {
						startChan <- true
					}
					d.endpointsLearning[lEP.EndpointID] = lEP
				} else {
					delete(d.endpointsLearning, lEP.EndpointID)
					if len(d.endpointsLearning) == 0 {
						stopChan1 <- true
					}
				}
				d.endpointsLearningMU.Unlock()
			}
		}
	}()

	go func() {
		var events *bpf.PerCpuEvents
		var err error
		for {
			select {
			case <-startChan:
				log.Info("Starting monitoring traffic")
				events, err = bpf.NewPerCpuEvents(bpf.DefaultPerfEventConfig())
				if err != nil {
					log.Errorf("Error while starting monitor")
				}
				go func() {
					for {
						todo, err := events.Poll(5000)
						if err != nil {
							select {
							case <-eventStopped:
								log.Info("Monitor successfully stopped")
								return
							case <-time.Tick(time.Millisecond * 10):
								log.Error(err)
								return
							}
						}
						if todo > 0 {
							if err := events.ReadAll(d.receiveEvent, d.lostEvent); err != nil {
								log.Warningf("Error received while reading from perf buffer: %s", err)
							}
						}
					}
				}()
			case <-stopChan1:
				log.Info("All endpoints stopped learning traffic, stopping monitor...")
				events.CloseAll()
				eventStopped <- true
			}
		}
	}()

}
