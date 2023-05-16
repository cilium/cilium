// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

var (
	managedNeighborOnce   sync.Once
	managedNeighborResult error
)

// HaveManagedNeighbors returns nil if the host supports managed neighbor entries (NTF_EXT_MANAGED).
// On unexpected probe results this function will terminate with log.Fatal().
func HaveManagedNeighbors() error {
	managedNeighborOnce.Do(func() {
		ch := make(chan struct{})

		// In order to call haveManagedNeighbors safely, it has to be started
		// in a goroutine, so we can make sure the goroutine ends when the function exits.
		// This makes sure the underlying OS thread exits if we fail to restore it to the original netns.
		go func() {
			managedNeighborResult = haveManagedNeighbors()
			close(ch)
		}()
		<-ch // wait for probe to finish

		// if we encounter a different error than ErrNotSupported, terminate the agent.
		if managedNeighborResult != nil && !errors.Is(managedNeighborResult, ErrNotSupported) {
			log.WithError(managedNeighborResult).Fatal("failed to probe managed neighbor support")
		}
	})

	return managedNeighborResult
}

func haveManagedNeighbors() (outer error) {
	runtime.LockOSThread()
	oldns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current netns: %w", err)
	}
	defer oldns.Close()

	newns, err := netns.New()
	if err != nil {
		return fmt.Errorf("failed to create new netns: %w", err)
	}
	defer newns.Close()
	defer func() {
		// defer closes over named return variable err
		if nerr := netns.Set(oldns); nerr != nil {
			// The current goroutine is locked to an OS thread and we've failed
			// to undo state modifications to the thread. Returning without unlocking
			// the goroutine will make sure the underlying OS thread dies.
			outer = fmt.Errorf("error setting thread back to its original netns: %w (original error: %s)", nerr, outer)
			return
		}
		// only now that we have successfully changed the thread back to its
		// original state (netns) we can safely unlock the goroutine from its OS thread.
		runtime.UnlockOSThread()
	}()

	la := netlink.NewLinkAttrs()
	la.Name = "cilium-dummy"

	dummy := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummy); err != nil {
		return fmt.Errorf("failed to add dummy link: %w", err)
	}

	neigh := netlink.Neigh{
		LinkIndex: dummy.Index,
		IP:        net.IPv4(10, 1, 1, 1),
		Flags:     netlink.NTF_EXT_LEARNED,
		FlagsExt:  netlink.NTF_EXT_MANAGED,
	}

	if err := netlink.NeighAdd(&neigh); err != nil {
		return fmt.Errorf("failed to add neighbor: %w", err)
	}

	nl, err := netlink.NeighList(dummy.Index, 0)
	if err != nil {
		return fmt.Errorf("failed to list neighbors: %w", err)
	}

	for _, n := range nl {
		if n.IP.Equal(neigh.IP) && n.Flags == netlink.NTF_EXT_LEARNED && n.FlagsExt == netlink.NTF_EXT_MANAGED {
			return nil
		}
	}

	return ErrNotSupported
}
