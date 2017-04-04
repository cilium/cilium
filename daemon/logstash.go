// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
)

type LogstashStat struct {
	FromID  uint32
	From    string
	ToID    string
	Bytes   uint64
	Packets uint64
	Action  string
}

func newLogstashClient(addr string) net.Conn {
	i := 3
	for {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			if i >= 0 {
				log.Errorf("Error while connecting to Logstash address %s: %s", addr, err)
				if i == 0 {
					log.Info("Mutting Logstash connection errors but still retrying...")
				}
				i--
			}
		} else {
			log.Infof("Connection to Logstash %s successfully made", addr)
			return c
		}
		time.Sleep(10 * time.Second)
	}
}

func (d *Daemon) EnableLogstash(LogstashAddr string, refreshTime int) {
	readStats := func(c net.Conn) {
		defer func() {
			recover()
		}()
		for {
			timeToProcess1 := time.Now()

			allPes := map[uint16][]policymap.PolicyEntryDump{}
			d.endpointsMU.RLock()
			for _, ep := range d.endpoints {
				ep.Mutex.RLock()
				pes, err := ep.PolicyMap.DumpToSlice()
				if err != nil {
					continue
				}
				allPes[ep.ID] = pes
				ep.Mutex.RUnlock()
			}
			d.endpointsMU.RUnlock()
			lss := d.processStats(allPes)
			for _, ls := range lss {
				if err := json.NewEncoder(c).Encode(ls); err != nil {
					log.Errorf("Error while sending data to Logstash: %s", err)
					timeToProcess2 := time.Now()
					time.Sleep(time.Second*time.Duration(refreshTime) - timeToProcess2.Sub(timeToProcess1))
					return
				}
			}

			timeToProcess2 := time.Now()
			time.Sleep(time.Second*time.Duration(refreshTime) - timeToProcess2.Sub(timeToProcess1))
		}
	}
	for {
		c := newLogstashClient(LogstashAddr)
		readStats(c)
	}
}

func (d *Daemon) getInlineLabelStr(id policy.NumericIdentity) string {
	l, err := d.GetCachedLabelList(id)
	if err != nil {
		return ""
	}
	inlineLblSlice := []string{}
	for _, lbl := range l {
		inlineLblSlice = append(inlineLblSlice, lbl.String())
	}
	return strings.Join(inlineLblSlice, "\n")
}

func (d *Daemon) processStats(allPes map[uint16][]policymap.PolicyEntryDump) []LogstashStat {
	lss := []LogstashStat{}
	for k, v := range allPes {
		if len(v) == 0 {
			continue
		}
		for _, stat := range v {
			lss = append(lss, LogstashStat{
				FromID:  stat.ID,
				From:    d.getInlineLabelStr(policy.NumericIdentity(stat.ID)),
				ToID:    strconv.FormatUint(uint64(k), 10),
				Bytes:   stat.Bytes,
				Packets: stat.Packets,
				Action:  stat.PolicyEntry.String(),
			})
		}
	}
	return lss
}
