// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/lock"
)

// PrefixLengthCounter tracks references to prefix lengths, limited by the
// maxUniquePrefixes count. Neither of the IPv4 or IPv6 counters nested within
// may contain more keys than the specified maximum number of unique prefixes.
type PrefixLengthCounter struct {
	lock.RWMutex

	v4 IntCounter
	v6 IntCounter

	maxUniquePrefixes4 int
	maxUniquePrefixes6 int
}

// NewPrefixLengthCounter returns a new PrefixLengthCounter which limits
// insertions to the specified maximum number of unique prefix lengths.
func NewPrefixLengthCounter(maxUniquePrefixes6, maxUniquePrefixes4 int) *PrefixLengthCounter {
	return &PrefixLengthCounter{
		v4:                 make(IntCounter),
		v6:                 make(IntCounter),
		maxUniquePrefixes4: maxUniquePrefixes4,
		maxUniquePrefixes6: maxUniquePrefixes6,
	}
}

func createIPNet(ones, bits int) netip.Prefix {
	var addr netip.Addr
	switch bits {
	case net.IPv4len * 8:
		addr = netip.IPv4Unspecified()
	case net.IPv6len * 8:
		addr = netip.IPv6Unspecified()
	default:
		// fall through to default library error
	}
	return netip.PrefixFrom(addr, ones)
}

// DefaultPrefixLengthCounter creates a default prefix length counter that
// already counts the minimum and maximum prefix lengths for IP hosts and
// default routes (ie, /32 and /0). As with NewPrefixLengthCounter, inesrtions
// are limited to the specified maximum number of unique prefix lengths.
func DefaultPrefixLengthCounter(maxUniquePrefixes6, maxUniquePrefixes4 int) *PrefixLengthCounter {
	counter := NewPrefixLengthCounter(maxUniquePrefixes6, maxUniquePrefixes4)

	defaultPrefixes := []netip.Prefix{
		// IPv4
		createIPNet(0, net.IPv4len*8),             // world
		createIPNet(net.IPv4len*8, net.IPv4len*8), // hosts

		// IPv6
		createIPNet(0, net.IPv6len*8),             // world
		createIPNet(net.IPv6len*8, net.IPv6len*8), // hosts
	}
	if _, err := counter.Add(defaultPrefixes); err != nil {
		panic(fmt.Errorf("Failed to create default prefix lengths: %s", err))
	}

	return counter
}

// checkLimits checks whether the specified new count of prefixes would exceed
// the specified limit on the maximum number of unique keys, and returns an
// error if it would exceed the limit.
func checkLimits(current, newCount, max int) error {
	if newCount > max {
		return fmt.Errorf("adding specified prefixes would result in too many prefix lengths (current: %d, result: %d, max: %d)",
			current, newCount, max)
	}
	return nil
}

// Add increments references to prefix lengths for the specified IPNets to the
// counter. If the maximum number of unique prefix lengths would be exceeded,
// returns an error.
//
// Returns true if adding these prefixes results in an increase in the total
// number of unique prefix lengths in the counter.
func (p *PrefixLengthCounter) Add(prefixes []netip.Prefix) (bool, error) {
	p.Lock()
	defer p.Unlock()

	// Assemble a map of references that need to be added
	newV4Counter := p.v4.DeepCopy()
	newV6Counter := p.v6.DeepCopy()
	newV4Prefixes := false
	newV6Prefixes := false
	for _, prefix := range prefixes {
		ones := prefix.Bits()
		bits := prefix.Addr().BitLen()

		switch bits {
		case net.IPv4len * 8:
			if newV4Counter.Add(ones) {
				newV4Prefixes = true
			}
		case net.IPv6len * 8:
			if newV6Counter.Add(ones) {
				newV6Prefixes = true
			}
		default:
			return false, fmt.Errorf("unsupported IPAddr bitlength %d", bits)
		}
	}

	// Check if they can be added given the limit in place
	if newV4Prefixes {
		if err := checkLimits(len(p.v4), len(newV4Counter), p.maxUniquePrefixes4); err != nil {
			return false, err
		}
	}
	if newV6Prefixes {
		if err := checkLimits(len(p.v6), len(newV6Counter), p.maxUniquePrefixes6); err != nil {
			return false, err
		}
	}

	// Set and return whether anything changed
	p.v4 = newV4Counter
	p.v6 = newV6Counter
	return newV4Prefixes || newV6Prefixes, nil
}

// Delete reduces references to prefix lengths in the the specified IPNets from
// the counter. Returns true if removing references to these prefix lengths
// would result in a decrese in the total number of unique prefix lengths in
// the counter.
func (p *PrefixLengthCounter) Delete(prefixes []netip.Prefix) (changed bool) {
	p.Lock()
	defer p.Unlock()

	for _, prefix := range prefixes {
		ones := prefix.Bits()
		bits := prefix.Addr().BitLen()
		switch bits {
		case net.IPv4len * 8:
			if p.v4.Delete(ones) {
				changed = true
			}
		case net.IPv6len * 8:
			if p.v6.Delete(ones) {
				changed = true
			}
		}
	}

	return changed
}

// ToBPFData converts the counter into a set of prefix lengths that the BPF
// datapath can use for LPM lookup.
func (p *PrefixLengthCounter) ToBPFData() (s6, s4 []int) {
	p.RLock()
	defer p.RUnlock()

	return p.v6.ToBPFData(), p.v4.ToBPFData()
}
