// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package link

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
)

var (
	// linkCache is the singleton instance of the LinkCache, only needed to
	// ensure that the single controller used to update the LinkCache is
	// triggered exactly once and the same instance is handed to all users.
	linkCache LinkCache
	once      sync.Once
)

// DeleteByName deletes the interface with the name ifName.
func DeleteByName(ifName string) error {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return fmt.Errorf("failed to delete %q: %v", ifName, err)
	}

	return nil
}

// Rename renames a network link
func Rename(curName, newName string) error {
	link, err := netlink.LinkByName(curName)
	if err != nil {
		return err
	}

	return netlink.LinkSetName(link, newName)
}

func GetHardwareAddr(ifName string) (mac.MAC, error) {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, err
	}
	return mac.MAC(iface.Attrs().HardwareAddr), nil
}

func GetIfIndex(ifName string) (uint32, error) {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return 0, err
	}
	return uint32(iface.Attrs().Index), nil
}

type LinkCache struct {
	mu          lock.RWMutex
	indexToName map[int]string
}

// NewLinkCache begins monitoring local interfaces for changes in order to
// track local link information.
func NewLinkCache() *LinkCache {
	once.Do(func() {
		linkCache = LinkCache{}
		controller.NewManager().UpdateController("link-cache",
			controller.ControllerParams{
				RunInterval: 15 * time.Second,
				DoFunc: func(ctx context.Context) error {
					return linkCache.syncCache()
				},
			},
		)
	})

	return &linkCache
}

func (c *LinkCache) syncCache() error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}

	indexToName := make(map[int]string, len(links))
	for _, link := range links {
		indexToName[link.Attrs().Index] = link.Attrs().Name
	}

	c.mu.Lock()
	c.indexToName = indexToName
	c.mu.Unlock()
	return nil
}

func (c *LinkCache) lookupName(ifIndex int) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	name, ok := c.indexToName[ifIndex]
	return name, ok
}

// GetIfNameCached returns the name of an interface (if it exists) by looking
// it up in a regularly updated cache. The return result is the same as a map
// lookup, ie nil, false if there is no entry cached for this ifindex.
func (c *LinkCache) GetIfNameCached(ifIndex int) (string, bool) {
	return c.lookupName(ifIndex)
}

// Name returns the name of a link by looking up the 'LinkCache', or returns a
// string containing the ifindex on cache miss.
func (c *LinkCache) Name(ifIndex uint32) string {
	if name, ok := c.lookupName(int(ifIndex)); ok {
		return name
	}
	return strconv.Itoa(int(ifIndex))
}
