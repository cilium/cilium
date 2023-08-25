package critbitgo

import (
	"net"
)

var (
	mask32  = net.IPMask{0xff, 0xff, 0xff, 0xff}
	mask128 = net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

// IP routing table.
type Net struct {
	trie *Trie
}

// Add a route.
// If `r` is not IPv4/IPv6 network, returns an error.
func (n *Net) Add(r *net.IPNet, value interface{}) (err error) {
	var ip net.IP
	if ip, _, err = netValidateIPNet(r); err == nil {
		n.trie.Set(netIPNetToKey(ip, r.Mask), value)
	}
	return
}

// Add a route.
// If `s` is not CIDR notation, returns an error.
func (n *Net) AddCIDR(s string, value interface{}) (err error) {
	var r *net.IPNet
	if _, r, err = net.ParseCIDR(s); err == nil {
		n.Add(r, value)
	}
	return
}

// Delete a specific route.
// If `r` is not IP4/IPv6 network or a route is not found, `ok` is false.
func (n *Net) Delete(r *net.IPNet) (value interface{}, ok bool, err error) {
	var ip net.IP
	if ip, _, err = netValidateIPNet(r); err == nil {
		value, ok = n.trie.Delete(netIPNetToKey(ip, r.Mask))
	}
	return
}

// Delete a specific route.
// If `s` is not CIDR notation or a route is not found, `ok` is false.
func (n *Net) DeleteCIDR(s string) (value interface{}, ok bool, err error) {
	var r *net.IPNet
	if _, r, err = net.ParseCIDR(s); err == nil {
		value, ok, err = n.Delete(r)
	}
	return
}

// Get a specific route.
// If `r` is not IPv4/IPv6 network or a route is not found, `ok` is false.
func (n *Net) Get(r *net.IPNet) (value interface{}, ok bool, err error) {
	var ip net.IP
	if ip, _, err = netValidateIPNet(r); err == nil {
		value, ok = n.trie.Get(netIPNetToKey(ip, r.Mask))
	}
	return
}

// Get a specific route.
// If `s` is not CIDR notation or a route is not found, `ok` is false.
func (n *Net) GetCIDR(s string) (value interface{}, ok bool, err error) {
	var r *net.IPNet
	if _, r, err = net.ParseCIDR(s); err == nil {
		value, ok, err = n.Get(r)
	}
	return
}

// Return a specific route by using the longest prefix matching.
// If `r` is not IPv4/IPv6 network or a route is not found, `route` is nil.
func (n *Net) Match(r *net.IPNet) (route *net.IPNet, value interface{}, err error) {
	var ip net.IP
	if ip, _, err = netValidateIP(r.IP); err == nil {
		if k, v := n.match(netIPNetToKey(ip, r.Mask)); k != nil {
			route = netKeyToIPNet(k)
			value = v
		}
	}
	return
}

// Return a specific route by using the longest prefix matching.
// If `s` is not CIDR notation, or a route is not found, `route` is nil.
func (n *Net) MatchCIDR(s string) (route *net.IPNet, value interface{}, err error) {
	var r *net.IPNet
	if _, r, err = net.ParseCIDR(s); err == nil {
		route, value, err = n.Match(r)
	}
	return
}

// Return a bool indicating whether a route would be found
func (n *Net) ContainedIP(ip net.IP) (contained bool, err error) {
	k, _, err := n.matchIP(ip)
	contained = k != nil
	return
}

// Return a specific route by using the longest prefix matching.
// If `ip` is invalid IP, or a route is not found, `route` is nil.
func (n *Net) MatchIP(ip net.IP) (route *net.IPNet, value interface{}, err error) {
	k, v, err := n.matchIP(ip)
	if k != nil {
		route = netKeyToIPNet(k)
		value = v
	}
	return
}

func (n *Net) matchIP(ip net.IP) (k []byte, v interface{}, err error) {
	var isV4 bool
	ip, isV4, err = netValidateIP(ip)
	if err != nil {
		return
	}
	var mask net.IPMask
	if isV4 {
		mask = mask32
	} else {
		mask = mask128
	}
	k, v = n.match(netIPNetToKey(ip, mask))
	return
}

func (n *Net) match(key []byte) ([]byte, interface{}) {
	if n.trie.size > 0 {
		if node := lookup(&n.trie.root, key, false); node != nil {
			return node.external.key, node.external.value
		}
	}
	return nil, nil
}

func lookup(p *node, key []byte, backtracking bool) *node {
	if p.internal != nil {
		var direction int
		if p.internal.offset == len(key)-1 {
			// selecting the larger side when comparing the mask
			direction = 1
		} else if backtracking {
			direction = 0
		} else {
			direction = p.internal.direction(key)
		}

		if c := lookup(&p.internal.child[direction], key, backtracking); c != nil {
			return c
		}
		if direction == 1 {
			// search other node
			return lookup(&p.internal.child[0], key, true)
		}
		return nil
	} else {
		nlen := len(p.external.key)
		if nlen != len(key) {
			return nil
		}

		// check mask
		mask := p.external.key[nlen-1]
		if mask > key[nlen-1] {
			return nil
		}

		// compare both keys with mask
		div := int(mask >> 3)
		for i := 0; i < div; i++ {
			if p.external.key[i] != key[i] {
				return nil
			}
		}
		if mod := uint(mask & 0x07); mod > 0 {
			bit := 8 - mod
			if p.external.key[div] != key[div]&(0xff>>bit<<bit) {
				return nil
			}
		}
		return p
	}
}

// Walk iterates routes from a given route.
// handle is called with arguments route and value (if handle returns `false`, the iteration is aborted)
func (n *Net) Walk(r *net.IPNet, handle func(*net.IPNet, interface{}) bool) {
	var key []byte
	if r != nil {
		if ip, _, err := netValidateIPNet(r); err == nil {
			key = netIPNetToKey(ip, r.Mask)
		}
	}
	n.trie.Walk(key, func(key []byte, value interface{}) bool {
		return handle(netKeyToIPNet(key), value)
	})
}

// WalkPrefix interates routes that have a given prefix.
// handle is called with arguments route and value (if handle returns `false`, the iteration is aborted)
func (n *Net) WalkPrefix(r *net.IPNet, handle func(*net.IPNet, interface{}) bool) {
	var prefix []byte
	var div int
	var bit uint
	if r != nil {
		if ip, _, err := netValidateIPNet(r); err == nil {
			prefix = netIPNetToKey(ip, r.Mask)
			mask := prefix[len(prefix)-1]
			div = int(mask >> 3)
			if mod := uint(mask & 0x07); mod != 0 {
				bit = 8 - mod
			}
		}
	}
	wrapper := func(key []byte, value interface{}) bool {
		if bit != 0 {
			if prefix[div]>>bit != key[div]>>bit {
				return false
			}
		}
		return handle(netKeyToIPNet(key), value)
	}
	n.trie.Allprefixed(prefix[0:div], wrapper)
}

func walkMatch(p *node, key []byte, handle func(*net.IPNet, interface{}) bool) bool {
	if p.internal != nil {
		if !walkMatch(&p.internal.child[0], key, handle) {
			return false
		}

		if p.internal.offset >= len(key)-1 || key[p.internal.offset]&p.internal.bit > 0 {
			return walkMatch(&p.internal.child[1], key, handle)
		}
		return true
	}

	mask := p.external.key[len(p.external.key)-1]
	if key[len(key)-1] < mask {
		return true
	}

	div := int(mask >> 3)
	for i := 0; i < div; i++ {
		if p.external.key[i] != key[i] {
			return true
		}
	}

	if mod := uint(mask & 0x07); mod > 0 {
		bit := 8 - mod
		if p.external.key[div] != key[div]&(0xff>>bit<<bit) {
			return true
		}
	}
	return handle(netKeyToIPNet(p.external.key), p.external.value)
}

// WalkMatch interates routes that match a given route.
// handle is called with arguments route and value (if handle returns `false`, the iteration is aborted)
func (n *Net) WalkMatch(r *net.IPNet, handle func(*net.IPNet, interface{}) bool) {
	if n.trie.size > 0 {
		walkMatch(&n.trie.root, netIPNetToKey(r.IP, r.Mask), handle)
	}
}

// Deletes all routes.
func (n *Net) Clear() {
	n.trie.Clear()
}

// Returns number of routes.
func (n *Net) Size() int {
	return n.trie.Size()
}

// Create IP routing table
func NewNet() *Net {
	return &Net{NewTrie()}
}

func netValidateIP(ip net.IP) (nIP net.IP, isV4 bool, err error) {
	if v4 := ip.To4(); v4 != nil {
		nIP = v4
		isV4 = true
	} else if ip.To16() != nil {
		nIP = ip
	} else {
		err = &net.AddrError{Err: "Invalid IP address", Addr: ip.String()}
	}
	return
}

func netValidateIPNet(r *net.IPNet) (nIP net.IP, isV4 bool, err error) {
	if r == nil {
		err = &net.AddrError{Err: "IP network is nil"}
		return
	}
	return netValidateIP(r.IP)
}

func netIPNetToKey(ip net.IP, mask net.IPMask) []byte {
	// +--------------+------+
	// | ip address.. | mask |
	// +--------------+------+
	ones, _ := mask.Size()
	return append(ip, byte(ones))
}

func netKeyToIPNet(k []byte) *net.IPNet {
	iplen := len(k) - 1
	return &net.IPNet{
		IP:   net.IP(k[:iplen]),
		Mask: net.CIDRMask(int(k[iplen]), iplen*8),
	}
}
