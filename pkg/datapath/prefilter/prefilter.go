// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package prefilter

import (
	"fmt"
	"io"
	"net"
	"path"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/probe"
)

type preFilterMapType int

const (
	prefixesV4Dyn preFilterMapType = iota
	prefixesV4Fix
	prefixesV6Dyn
	prefixesV6Fix
	mapCount
)

const (
	// Arbitrary chosen for now. We don't preallocate elements,
	// so we could bump the limit if needed later on.
	maxLKeys = 1024 * 64
	maxHKeys = 1024 * 1024 * 20
)

type preFilterMaps [mapCount]*cidrmap.CIDRMap

type preFilterConfig struct {
	dyn4Enabled bool
	dyn6Enabled bool
	fix4Enabled bool
	fix6Enabled bool
}

// PreFilter holds global info on related CIDR maps participating in prefilter
type PreFilter struct {
	maps     preFilterMaps
	config   preFilterConfig
	revision int64
	mutex    lock.RWMutex
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "prefilter")
)

// WriteConfig dumps the configuration for the corresponding header file
func (p *PreFilter) WriteConfig(fw io.Writer) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	fmt.Fprintf(fw, "#define CIDR4_HMAP_ELEMS %d\n", maxHKeys)
	fmt.Fprintf(fw, "#define CIDR4_LMAP_ELEMS %d\n", maxLKeys)

	fmt.Fprintf(fw, "#define CIDR4_HMAP_NAME %s\n", path.Base(p.maps[prefixesV4Fix].String()))
	fmt.Fprintf(fw, "#define CIDR4_LMAP_NAME %s\n", path.Base(p.maps[prefixesV4Dyn].String()))
	fmt.Fprintf(fw, "#define CIDR6_HMAP_NAME %s\n", path.Base(p.maps[prefixesV6Fix].String()))
	fmt.Fprintf(fw, "#define CIDR6_LMAP_NAME %s\n", path.Base(p.maps[prefixesV6Dyn].String()))

	if p.config.fix4Enabled {
		fmt.Fprintf(fw, "#define CIDR4_FILTER\n")
		if p.config.dyn4Enabled {
			fmt.Fprintf(fw, "#define CIDR4_LPM_PREFILTER\n")
		}
	}
	if p.config.fix6Enabled {
		fmt.Fprintf(fw, "#define CIDR6_FILTER\n")
		if p.config.dyn6Enabled {
			fmt.Fprintf(fw, "#define CIDR6_LPM_PREFILTER\n")
		}
	}
}

func (p *PreFilter) dumpOneMap(which preFilterMapType, to []string) []string {
	if p.maps[which] == nil {
		return to
	}
	return p.maps[which].CIDRDump(to)
}

// Dump dumps revision and CIDRs as string slice of all participating maps
func (p *PreFilter) Dump(to []string) ([]string, int64) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	for i := prefixesV4Dyn; i < mapCount; i++ {
		to = p.dumpOneMap(i, to)
	}
	return to, p.revision
}

func (p *PreFilter) selectMap(ones, bits int) preFilterMapType {
	if bits == net.IPv4len*8 {
		if ones == bits {
			return prefixesV4Fix
		}
		return prefixesV4Dyn
	} else if bits == net.IPv6len*8 {
		if ones == bits {
			return prefixesV6Fix
		}
		return prefixesV6Dyn
	} else {
		return mapCount
	}
}

// Insert inserts slice of CIDRs (doh!) for the latest revision
func (p *PreFilter) Insert(revision int64, cidrs []net.IPNet) error {
	var undoQueue []net.IPNet
	var ret error

	p.mutex.Lock()
	defer p.mutex.Unlock()
	if revision != 0 && p.revision != revision {
		return fmt.Errorf("Latest revision is %d not %d", p.revision, revision)
	}
	for _, cidr := range cidrs {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		if which == mapCount || p.maps[which] == nil {
			ret = fmt.Errorf("No map enabled for CIDR string %s", cidr.String())
			break
		}
		err := p.maps[which].InsertCIDR(cidr)
		if err != nil {
			ret = fmt.Errorf("Error inserting CIDR string %s: %s", cidr.String(), err)
			break
		} else {
			undoQueue = append(undoQueue, cidr)
		}
	}
	if ret == nil {
		p.revision++
		return ret
	}
	for _, cidr := range undoQueue {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		p.maps[which].DeleteCIDR(cidr)
	}
	return ret
}

// Delete deletes slice of CIDRs (doh!) for the latest revision
func (p *PreFilter) Delete(revision int64, cidrs []net.IPNet) error {
	var undoQueue []net.IPNet
	var ret error

	p.mutex.Lock()
	defer p.mutex.Unlock()
	if revision != 0 && p.revision != revision {
		return fmt.Errorf("Latest revision is %d not %d", p.revision, revision)
	}
	for _, cidr := range cidrs {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		if which == mapCount || p.maps[which] == nil {
			return fmt.Errorf("No map enabled for CIDR string %s", cidr.String())
		}
		// Lets check obvious cases first, so we don't need to painfully unroll
		if p.maps[which].CIDRExists(cidr) == false {
			return fmt.Errorf("No map entry for CIDR string %s", cidr.String())
		}
	}
	for _, cidr := range cidrs {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		err := p.maps[which].DeleteCIDR(cidr)
		if err != nil {
			ret = fmt.Errorf("Error deleting CIDR string %s: %s", cidr.String(), err)
			break
		} else {
			undoQueue = append(undoQueue, cidr)
		}
	}
	if ret == nil {
		p.revision++
		return ret
	}
	for _, cidr := range undoQueue {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		p.maps[which].InsertCIDR(cidr)
	}
	return ret
}

func (p *PreFilter) initOneMap(which preFilterMapType) error {
	var prefixdyn bool
	var prefixlen int
	var maxelems uint32
	var path string
	var err error
	var skip bool

	switch which {
	case prefixesV4Dyn:
		prefixlen = net.IPv4len * 8
		prefixdyn = true
		maxelems = maxLKeys
		path = bpf.MapPath(cidrmap.MapName + "v4_dyn")
		skip = p.config.dyn4Enabled == false
	case prefixesV4Fix:
		prefixlen = net.IPv4len * 8
		prefixdyn = false
		maxelems = maxHKeys
		path = bpf.MapPath(cidrmap.MapName + "v4_fix")
		skip = p.config.fix4Enabled == false
	case prefixesV6Dyn:
		prefixlen = net.IPv6len * 8
		prefixdyn = true
		maxelems = maxLKeys
		path = bpf.MapPath(cidrmap.MapName + "v6_dyn")
		skip = p.config.dyn6Enabled == false
	case prefixesV6Fix:
		prefixlen = net.IPv6len * 8
		prefixdyn = false
		maxelems = maxHKeys
		path = bpf.MapPath(cidrmap.MapName + "v6_fix")
		skip = p.config.fix4Enabled == false
	}
	if skip == false {
		p.maps[which], err = cidrmap.OpenMapElems(path, prefixlen, prefixdyn, maxelems)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *PreFilter) init() (*PreFilter, error) {
	for i := prefixesV4Dyn; i < mapCount; i++ {
		if err := p.initOneMap(i); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// NewPreFilter returns prefilter handle
func NewPreFilter() (*PreFilter, error) {
	haveLPM := probe.HaveFullLPM()
	if !haveLPM {
		log.Warning("Kernel too old for full LPM map support. Needs kernel 4.16 or higher. Only enabling /32 and /128 prefixes for prefilter.")
	}
	c := preFilterConfig{
		dyn4Enabled: haveLPM,
		dyn6Enabled: haveLPM,
		fix4Enabled: true,
		fix6Enabled: true,
	}
	p := &PreFilter{
		revision: 1,
		config:   c,
	}
	// Only needed here given we access pinned maps.
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.init()
}
