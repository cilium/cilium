// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"

	"github.com/cilium/hive/cell"
)

type MTUManager struct {
	mtuParams
	Config *Configuration

	localNode     atomic.Pointer[v2.CiliumNode]
	localNodeInit chan struct{}
}

// The MTU on these devices is set by us indirectly, so we don't want to
// use them as source for MTU detection since that would create a loop.
var excludedDevices = []string{
	defaults.VxlanDevice,
	defaults.GeneveDevice,
	defaults.IPIPv4Device,
	defaults.IPIPv6Device,
}

// Exclude the dummy device type when evaluating the MTU. The dummy device
// is for the local traffic but the local traffic does not really
// go through the dummy device.
var excludedDevicesType = []string{
	"dummy",
}

func (m *MTUManager) Updater(ctx context.Context, health cell.Health) error {
	for {
		devs, devsChanged := tables.SelectedDevices(m.Devices, m.DB.ReadTxn())

		baseMTU := MaxMTU
		consideredDevices := m.consideredDevices(devs)
		deviceNames := make([]string, 0, len(consideredDevices))
		for _, dev := range consideredDevices {
			baseMTU = min(baseMTU, dev.MTU)
			deviceNames = append(deviceNames, dev.Name)
		}
		m.Log.Debug("Detected base MTU from devices",
			logfields.Devices, deviceNames,
			logfields.MTU, baseMTU,
		)

		routeMTU := m.Config.Calculate(baseMTU)

		txn := m.DB.WriteTxn(m.MTUTable)

		changed := false

		// Update the IPv4 default route MTU if it has changed
		existing, _, found := m.MTUTable.Get(txn, MTURouteIndex.Query(DefaultPrefixV4))
		if !found || existing.DeviceMTU != routeMTU.DeviceMTU {
			routeMTU.Prefix = DefaultPrefixV4
			_, _, err := m.MTUTable.Insert(txn, routeMTU)
			if err != nil {
				txn.Abort()
				return err
			}
			changed = true
		}

		// Update the IPv6 default route MTU if it has changed
		existing, _, found = m.MTUTable.Get(txn, MTURouteIndex.Query(DefaultPrefixV6))
		if !found || existing.DeviceMTU != routeMTU.DeviceMTU {
			routeMTU.Prefix = DefaultPrefixV6
			_, _, err := m.MTUTable.Insert(txn, routeMTU)
			if err != nil {
				txn.Abort()
				return err
			}
			changed = true
		}

		txn.Commit()

		if changed {
			health.OK(fmt.Sprintf("MTU updated (%d)", routeMTU.DeviceMTU))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-devsChanged:
		case <-m.localNodeInit:
		}
	}
}

func (m *MTUManager) needLocalCiliumNode() bool {
	return m.mtuParams.DaemonConfig.IPAM == ipamOption.IPAMENI
}

func (m *MTUManager) observeLocalCiliumNode(ctx context.Context, event resource.Event[*v2.CiliumNode]) error {
	if event.Kind != resource.Upsert {
		event.Done(nil)
		return nil
	}

	// Ignore update events if the node local IPs is not yet know, which might not happen
	// in the first event.
	hasInternalIP := false
	for _, addr := range event.Object.Spec.Addresses {
		if addr.Type == addressing.NodeInternalIP {
			hasInternalIP = true
			break
		}
	}
	if !hasInternalIP {
		event.Done(nil)
		return nil
	}

	old := m.localNode.Swap(event.Object)
	if old == nil {
		// Notify the updater that the local node is now known, and that we should re-evaluate
		// the MTU.
		select {
		case <-ctx.Done():
			return nil
		case m.localNodeInit <- struct{}{}:
		}

		m.localNodeInit = nil
	}
	event.Done(nil)

	return nil
}

func (m *MTUManager) consideredDevices(devs []*tables.Device) []*tables.Device {
	switch m.mtuParams.DaemonConfig.IPAM {
	case ipamOption.IPAMENI:
		// In ENI mode, secondary devices are managed by Cilium, so we need to exclude them
		// from the list of devices to consider for MTU calculation. Only the primary ENI
		// always exists, and can be used for MTU auto detection.

		// Get the local node
		localNode := m.localNode.Load()
		if localNode == nil {
			// There is a chance that the local node is not yet known, and we cannot wait since
			// the datapath initialization depends on having an MTU known, and the node logic
			// which creates the CiliumNode object waits for the datapath to be initialized.
			// So we initially consider all devices, once the local node is known we will re-evaluate
			// the devices which should fix the MTU.
			break
		}

		var internalIP string
		for _, addr := range localNode.Spec.Addresses {
			if addr.Type == addressing.NodeInternalIP {
				internalIP = addr.IP
				break
			}
		}
		// If we don't have the internal IP yet, we cannot exclude any devices
		if internalIP == "" {
			break
		}

		for _, eni := range localNode.Status.ENI.ENIs {
			// Use the primary IP of the node to tell which ENI is the primary
			isPrimary := eni.IP == internalIP
			if isPrimary {
				continue
			}

			// Names of ENIs and actual device doesn't match, use MAC address to match
			// secondary ENIs to the actual device
			mac, err := net.ParseMAC(eni.MAC)
			if err != nil {
				m.Log.Error("Failed to parse MAC address", logfields.Error, err)
				continue
			}

			// Remove the device with the MAC address of the secondary ENI
			devs = slices.DeleteFunc(devs, func(dev *tables.Device) bool {
				return bytes.Equal(dev.HardwareAddr, mac)
			})
		}
	}

	// Exclude devices which are created/managed by Cilium and dummy devices on the host.
	return slices.DeleteFunc(devs, func(dev *tables.Device) bool {
		return slices.Contains(excludedDevices, dev.Name) || slices.Contains(excludedDevicesType, dev.Type)
	})
}
