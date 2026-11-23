// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package prefilter

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"

	datapathmaps "github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

// PreFilter an interface for an XDP pre-filter.
type PreFilter interface {
	Enabled() bool
	Dump(to []string) ([]string, int64)
	Insert(revision int64, cidrs []net.IPNet) error
	Delete(revision int64, cidrs []net.IPNet) error
}

type preFilterMapSpec struct {
	name      string
	prefixlen int
	prefixdyn bool
}

var preFilterMapSpecs = []preFilterMapSpec{
	{datapathmaps.CiliumCIDRV4Dyn, net.IPv4len * 8, true},
	{datapathmaps.CiliumCIDRV4Fix, net.IPv4len * 8, false},
	{datapathmaps.CiliumCIDRV6Dyn, net.IPv6len * 8, true},
	{datapathmaps.CiliumCIDRV6Fix, net.IPv6len * 8, false},
}

// PreFilter holds global info on related CIDR maps participating in prefilter
type preFilter struct {
	logger   *slog.Logger
	maps     map[string]*cidrmap.CIDRMap
	revision int64
	mutex    lock.RWMutex

	enabled bool
}

func (p *preFilter) dumpOneMap(name string, to []string) []string {
	if p.maps[name] == nil {
		return to
	}
	return p.maps[name].CIDRDump(to)
}

func (p *preFilter) Enabled() bool {
	return p.enabled
}

// Dump dumps revision and CIDRs as string slice of all participating maps
func (p *preFilter) Dump(to []string) ([]string, int64) {
	if !p.enabled {
		return to, 0
	}

	p.mutex.RLock()
	defer p.mutex.RUnlock()
	for _, spec := range preFilterMapSpecs {
		to = p.dumpOneMap(spec.name, to)
	}
	return to, p.revision
}

func (p *preFilter) selectMap(ones, bits int) (string, bool) {
	if bits == net.IPv4len*8 {
		if ones == bits {
			return datapathmaps.CiliumCIDRV4Fix, true
		}
		return datapathmaps.CiliumCIDRV4Dyn, true
	} else if bits == net.IPv6len*8 {
		if ones == bits {
			return datapathmaps.CiliumCIDRV6Fix, true
		}
		return datapathmaps.CiliumCIDRV6Dyn, true
	} else {
		return "", false
	}
}

// Insert inserts slice of CIDRs (doh!) for the latest revision
func (p *preFilter) Insert(revision int64, cidrs []net.IPNet) error {
	if !p.enabled {
		return fmt.Errorf("Prefilter is not enabled")
	}

	var undoQueue []net.IPNet
	var ret error

	p.mutex.Lock()
	defer p.mutex.Unlock()
	if revision != 0 && p.revision != revision {
		return fmt.Errorf("Latest revision is %d not %d", p.revision, revision)
	}
	for _, cidr := range cidrs {
		ones, bits := cidr.Mask.Size()
		name, ok := p.selectMap(ones, bits)
		if !ok || p.maps[name] == nil {
			ret = fmt.Errorf("No map enabled for CIDR string %s", cidr.String())
			break
		}
		err := p.maps[name].InsertCIDR(cidr)
		if err != nil {
			ret = fmt.Errorf("Error inserting CIDR string %s: %w", cidr.String(), err)
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
		name, _ := p.selectMap(ones, bits)
		p.maps[name].DeleteCIDR(cidr)
	}
	return ret
}

// Delete deletes slice of CIDRs (doh!) for the latest revision
func (p *preFilter) Delete(revision int64, cidrs []net.IPNet) error {
	if !p.enabled {
		return fmt.Errorf("Prefilter is not enabled")
	}

	var undoQueue []net.IPNet
	var ret error

	p.mutex.Lock()
	defer p.mutex.Unlock()
	if revision != 0 && p.revision != revision {
		return fmt.Errorf("Latest revision is %d not %d", p.revision, revision)
	}
	for _, cidr := range cidrs {
		ones, bits := cidr.Mask.Size()
		name, ok := p.selectMap(ones, bits)
		if !ok || p.maps[name] == nil {
			return fmt.Errorf("No map enabled for CIDR string %s", cidr.String())
		}
		// Lets check obvious cases first, so we don't need to painfully unroll
		if !p.maps[name].CIDRExists(cidr) {
			return fmt.Errorf("No map entry for CIDR string %s", cidr.String())
		}
	}
	for _, cidr := range cidrs {
		ones, bits := cidr.Mask.Size()
		name, _ := p.selectMap(ones, bits)
		err := p.maps[name].DeleteCIDR(cidr)
		if err != nil {
			ret = fmt.Errorf("Error deleting CIDR string %s: %w", cidr.String(), err)
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
		name, _ := p.selectMap(ones, bits)
		p.maps[name].InsertCIDR(cidr)
	}
	return ret
}

func (p *preFilter) initOneMap(reg *registry.MapRegistry, spec preFilterMapSpec) error {
	m, err := cidrmap.OpenMapFromRegistry(reg, p.logger, spec.name, spec.prefixlen, spec.prefixdyn)
	if err != nil {
		return err
	}
	p.maps[spec.name] = m
	return nil
}

func (p *preFilter) init(reg *registry.MapRegistry) error {
	for _, spec := range preFilterMapSpecs {
		if err := p.initOneMap(reg, spec); err != nil {
			return err
		}
	}
	return nil
}

// newPreFilter returns prefilter handle
func newPreFilter(
	logger *slog.Logger,
	config *option.DaemonConfig,
	lifecycle cell.Lifecycle,
	reg *registry.MapRegistry,
) PreFilter {
	p := &preFilter{
		logger:   logger,
		maps:     make(map[string]*cidrmap.CIDRMap),
		revision: 1,
		enabled:  config.EnableXDPPrefilter,
	}

	if config.EnableXDPPrefilter {
		lifecycle.Append(cell.Hook{
			OnStart: func(hc cell.HookContext) error {
				// Only needed here given we access pinned maps.
				p.mutex.Lock()
				defer p.mutex.Unlock()
				return p.init(reg)
			},
		})
	}

	return p
}
