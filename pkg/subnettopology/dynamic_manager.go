package subnettopology

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"
	"github.com/cilium/workerpool"
)

type dynamicManager struct {
	mu sync.Mutex

	logger   *slog.Logger
	filepath string

	hash    uint64
	subnets []subnet

	wp *workerpool.WorkerPool

	m *Map
}

type subnet struct {
	ip     net.IP
	prefix net.IPMask
}

func registerDynamicManager(p Params) error {
	tm := &dynamicManager{
		logger: p.Logger.With(
			logfields.LogSubsys, "subnet-topology",
		),
		filepath: p.DaemonConfig.SubnetTopologyFilePath,
		m:        p.M,
	}
	p.Lifecycle.Append(tm)
	return nil
}

func (tm *dynamicManager) Start(ctx cell.HookContext) error {
	tm.logger.Info("Starting subnet topology map")
	if tm.filepath == "" {
		tm.logger.Warn("No subnet topology file path configured, skipping watcher")
		return nil
	}
	// Open map.
	if err := tm.m.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to open subnet topology map: %w", err)
	}
	w := newWatcher(tm.logger, tm.filepath, tm.onUpdate)

	tm.wp = workerpool.New(1)
	if err := tm.wp.Submit("subnet-topology-watcher", w.watch); err != nil {
		return fmt.Errorf("failed to start subnet topology watcher: %w", err)
	}
	return nil
}

func (tm *dynamicManager) Stop(ctx cell.HookContext) error {
	tm.logger.Info("Stopping subnet topology map")
	if tm.wp != nil {
		tm.wp.Close()
	}
	return nil
}

func (tm *dynamicManager) onUpdate(newSubnet string, newHash uint64) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if newHash == tm.hash {
		// No change in hash, nothing to update.
		return nil
	}

	// Delete all entries from eBPF map.
	if err := tm.m.DeleteAll(); err != nil {
		return fmt.Errorf("failed to delete all entries from eBPF map: %w", err)
	}
	tm.logger.Info("Deleted all entries from eBPF map due to hash change", "oldHash", tm.hash, "newHash", newHash)

	// Parse new newSubnets.
	newSubnets, err := tm.parse(newSubnet)
	if err != nil {
		return fmt.Errorf("failed to parse new subnets: %w", err)
	}

	// Sync eBPF map.
	for _, subnet := range newSubnets {
		tm.logger.Info("Syncing eBPF map", "ip", subnet.ip.String(), "prefix", subnet.prefix.String(), "hash", newHash)
		k := NewKey(subnet.ip, subnet.prefix, 0)
		v := NewValue(1)
		if err := tm.m.Update(&k, &v); err != nil {
			return fmt.Errorf("invalid CIDR: %s", subnet.ip.String())
		}
	}

	tm.hash = newHash
	tm.subnets = newSubnets

	return nil
}

/*
Parse the subnet topology from the configuration.
Example format of newSubnet:
10.0.0.1/24,10.10.0.1/24;10.20.0.1/24;2001:0db8:85a3::/64
Maps to subnets:
| CIDR | Subnet ID |
|------|-----------|
| 10.0.0.1/24 | 1  |
| 10.10.0.1/24 | 1 |
| 10.20.0.1/24 | 2 |
| 2001:0db8:85a3::/64 | 3 |
*/
func (tm *dynamicManager) parse(newSubnet string) ([]subnet, error) {
	var subnets []subnet
	if newSubnet == "" {
		return subnets, nil
	}
	entries := strings.Split(newSubnet, ";")
	for _, entry := range entries {
		cidrs := strings.Split(entry, ",")
		for _, cidr := range cidrs {
			ip, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %s", cidr)
			}
			subnets = append(subnets, subnet{
				ip:     ip,
				prefix: ipNet.Mask,
			})
		}
	}
	return subnets, nil
}
