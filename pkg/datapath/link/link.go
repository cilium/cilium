// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package link

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// linkCache is the singleton instance of the LinkCache, only needed to
	// ensure that the single controller used to update the LinkCache is
	// triggered exactly once and the same instance is handed to all users.
	linkCache LinkCache
	once      sync.Once

	linkCacheControllerGroup = controller.NewGroup("link-cache")
)

// DeleteByName deletes the interface with the name ifName.
//
// Returns nil if the interface does not exist.
func DeleteByName(ifName string) error {
	iface, err := safenetlink.LinkByName(ifName)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to lookup %q: %w", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return fmt.Errorf("failed to delete %q: %w", ifName, err)
	}

	return nil
}

// Rename renames a network link
func Rename(curName, newName string) error {
	link, err := safenetlink.LinkByName(curName)
	if err != nil {
		return err
	}

	return netlink.LinkSetName(link, newName)
}

func GetHardwareAddr(ifName string) (mac.MAC, error) {
	iface, err := safenetlink.LinkByName(ifName)
	if err != nil {
		return nil, err
	}
	return mac.MAC(iface.Attrs().HardwareAddr), nil
}

func GetIfIndex(ifName string) (uint32, error) {
	iface, err := safenetlink.LinkByName(ifName)
	if err != nil {
		return 0, err
	}
	return uint32(iface.Attrs().Index), nil
}

type LinkCache struct {
	mu          lock.RWMutex
	indexToName map[int]string
	manager     *controller.Manager
}

var Cell = cell.Module(
	"link-cache",
	"Provides a cache of link names to ifindex mappings",

	cell.Provide(newLinkCache),
	cell.Invoke(registerLinkCacheHooks),
)

type linkCacheParams struct {
	cell.In
	Lifecycle cell.Lifecycle
}

func registerLinkCacheHooks(params linkCacheParams, cache *LinkCache) {
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			// Start the controller when the application starts
			cache.manager.UpdateController("link-cache",
				controller.ControllerParams{
					Group:       linkCacheControllerGroup,
					RunInterval: 15 * time.Second,
					DoFunc: func(ctx context.Context) error {
						return cache.syncCache()
					},
				},
			)
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			cache.Stop()
			return nil
		},
	})
}

func newLinkCache() *LinkCache {
	once.Do(func() {
		linkCache = LinkCache{
			indexToName: make(map[int]string),
			manager:     controller.NewManager(),
		}
	})

	return &linkCache
}

func NewLinkCache() *LinkCache {
	lc := newLinkCache()

	lc.manager.UpdateController("link-cache",
		controller.ControllerParams{
			Group:       linkCacheControllerGroup,
			RunInterval: 15 * time.Second,
			DoFunc: func(ctx context.Context) error {
				return linkCache.syncCache()
			},
		},
	)

	return lc
}

// Stop terminates the link cache controller
func (c *LinkCache) Stop() {
	c.manager.RemoveController("link-cache")
}

func (c *LinkCache) syncCache() error {
	links, err := safenetlink.LinkList()
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
