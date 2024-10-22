// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.

package ipaddr

import (
	"errors"
	"net"
)

// A Cursor represents a movable indicator on single or multiple
// prefixes.
type Cursor struct {
	curr, start, end ipv6Int
	pi               int
	ps               []Prefix
}

func (c *Cursor) set(pi int, ip net.IP) {
	c.pi = pi
	c.curr = ipToIPv6Int(ip.To16())
	c.start = ipToIPv6Int(c.ps[c.pi].IP.To16())
	if ip.To4() != nil {
		c.end = c.ps[c.pi].lastIPv4MappedIPv6Int()
	}
	if ip.To16() != nil && ip.To4() == nil {
		c.end = c.ps[c.pi].lastIPv6Int()
	}
}

// First returns the start position on c.
func (c *Cursor) First() *Position {
	return &Position{IP: c.ps[0].IP, Prefix: c.ps[0]}
}

// Last returns the end position on c.
func (c *Cursor) Last() *Position {
	return &Position{IP: c.ps[len(c.ps)-1].Last(), Prefix: c.ps[len(c.ps)-1]}
}

// List returns the list of prefixes on c.
func (c *Cursor) List() []Prefix {
	return c.ps
}

// Next turns to the next position on c.
// It returns nil at the end on c.
func (c *Cursor) Next() *Position {
	n := c.curr.cmp(&c.end)
	if n == 0 {
		if c.pi == len(c.ps)-1 {
			return nil
		}
		c.pi++
		c.curr = ipToIPv6Int(c.ps[c.pi].IP.To16())
		c.start = c.curr
		if c.ps[c.pi].IP.To4() != nil {
			c.end = c.ps[c.pi].lastIPv4MappedIPv6Int()
		}
		if c.ps[c.pi].IP.To16() != nil && c.ps[c.pi].IP.To4() == nil {
			c.end = c.ps[c.pi].lastIPv6Int()
		}
	} else {
		c.curr.incr()
	}
	return c.Pos()
}

// Pos returns the current position on c.
func (c *Cursor) Pos() *Position {
	return &Position{IP: c.curr.ip(), Prefix: c.ps[c.pi]}
}

// Prev turns to the previous position on c.
// It returns nil at the start on c.
func (c *Cursor) Prev() *Position {
	n := c.curr.cmp(&c.start)
	if n == 0 {
		if c.pi == 0 {
			return nil
		}
		c.pi--
		if c.ps[c.pi].IP.To4() != nil {
			c.curr = c.ps[c.pi].lastIPv4MappedIPv6Int()
			c.end = c.curr
		}
		if c.ps[c.pi].IP.To16() != nil && c.ps[c.pi].IP.To4() == nil {
			c.curr = c.ps[c.pi].lastIPv6Int()
			c.end = c.curr
		}
		c.start = ipToIPv6Int(c.ps[c.pi].IP.To16())
	} else {
		c.curr.decr()
	}
	return c.Pos()
}

// Reset resets all state and switches to ps.
// It uses the existing prefixes when ps is nil.
func (c *Cursor) Reset(ps []Prefix) {
	ps = newSortedPrefixes(ps, sortAscending, false)
	if len(ps) > 0 {
		c.ps = ps
	}
	c.set(0, c.ps[0].IP.To16())
}

// Set sets the current position on c to pos.
func (c *Cursor) Set(pos *Position) error {
	if pos == nil {
		return errors.New("invalid position")
	}
	pi := -1
	for i, p := range c.ps {
		if p.Equal(&pos.Prefix) {
			pi = i
			break
		}
	}
	if pi == -1 || !c.ps[pi].IPNet.Contains(pos.IP) {
		return errors.New("position out of range")
	}
	c.set(pi, pos.IP.To16())
	return nil
}

// NewCursor returns a new cursor.
func NewCursor(ps []Prefix) *Cursor {
	ps = newSortedPrefixes(ps, sortAscending, false)
	if len(ps) == 0 {
		return nil
	}
	c := &Cursor{ps: ps}
	c.set(0, c.ps[0].IP.To16())
	return c
}
