// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package macvlan

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

var (
	errInterfaceNotFound = errors.New("interface not found")
)

// netlinkLinkByIndex is a variable that can be mocked in tests
var netlinkLinkByIndex = netlink.LinkByIndex

type MacvlanManager struct {
	logger            *slog.Logger
	config            *v2alpha1.MacvlanDeviceManagerConfig
	netlinkLinkLister func() ([]netlink.Link, error)
}

func (m *MacvlanManager) init() error {
	m.logger.Debug(
		"initializing macvlan device manager",
	)

	return m.setupMacvlans(m.config.Ifaces)
}

func NewManager(logger *slog.Logger, cfg *v2alpha1.MacvlanDeviceManagerConfig, opts ...func(*MacvlanManager)) (*MacvlanManager, error) {
	mgr := &MacvlanManager{
		logger:            logger,
		config:            cfg,
		netlinkLinkLister: safenetlink.LinkList,
	}

	for _, opt := range opts {
		opt(mgr)
	}

	return mgr, mgr.init()
}

func (mgr *MacvlanManager) Type() types.DeviceManagerType {
	return types.DeviceManagerTypeMacvlan
}

// ListDevices scans the system to find macvlan sub-interfaces.
func (mgr *MacvlanManager) ListDevices() ([]types.Device, error) {
	links, err := mgr.netlinkLinkLister()
	if err != nil {
		return nil, err
	}

	var result []types.Device

	for _, link := range links {
		if link.Type() != "macvlan" {
			continue
		}

		// Skip down interfaces
		if link.Attrs().Flags&net.FlagUp == 0 {
			continue
		}

		macvlan, ok := link.(*netlink.Macvlan)
		if !ok {
			continue
		}

		// Get parent interface name
		parentLink, err := netlinkLinkByIndex(link.Attrs().ParentIndex)
		if err != nil {
			mgr.logger.Warn(
				"failed to get parent link for macvlan device",
				logfields.Device, link.Attrs().Name,
				logfields.Error, err,
			)
			continue
		}

		device := &MacvlanDevice{
			Name:            strings.ReplaceAll(link.Attrs().Name, ".", "-"),
			ParentName:      parentLink.Attrs().Name,
			KernelIfaceName: link.Attrs().Name,
			HWAddr:          link.Attrs().HardwareAddr.String(),
			MTU:             link.Attrs().MTU,
			Flags:           link.Attrs().Flags.String(),
			Mode:            macvlan.Mode,
		}

		result = append(result, device)
	}

	return result, nil
}

func (mgr *MacvlanManager) RestoreDevice(data []byte) (types.Device, error) {
	var dev MacvlanDevice
	if err := dev.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &dev, nil
}

type MacvlanDevice struct {
	Name            string
	ParentName      string
	KernelIfaceName string
	HWAddr          string
	MTU             int
	Flags           string
	Mode            netlink.MacvlanMode
}

func (d MacvlanDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	result := make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
	result[types.IfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.IfName())}
	result[types.KernelIfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.KernelIfName())}
	result[types.HWAddrLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.HWAddr)}
	result[types.MTULabel] = resourceapi.DeviceAttribute{IntValue: ptr.To(int64(d.MTU))}
	result[types.FlagsLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.Flags)}
	result[types.ParentIfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.ParentName)}
	result[types.MacVlanModeLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(macvlanModeToString(d.Mode))}

	return result
}

func (d MacvlanDevice) Setup(cfg types.DeviceConfig) error {
	// For macvlan, setup is minimal - the device is already created
	// We could potentially set MTU or other settings here if needed
	return nil
}

func (d MacvlanDevice) Free(cfg types.DeviceConfig) error {
	// For macvlan, we don't delete the device on free
	// The device is managed by the manager and persists
	return nil
}

func (d MacvlanDevice) Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool {
	if len(filter.DeviceManagers) != 0 && !slices.Contains(filter.DeviceManagers, types.DeviceManagerTypeMacvlan.String()) {
		return false
	}

	if len(filter.IfNames) != 0 && !slices.Contains(filter.IfNames, d.IfName()) {
		return false
	}

	return true
}

func (d MacvlanDevice) IfName() string {
	return d.Name
}

func (d MacvlanDevice) KernelIfName() string {
	return d.KernelIfaceName
}

func (d MacvlanDevice) MarshalBinary() (data []byte, err error) {
	return json.Marshal(d)
}

func (d *MacvlanDevice) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, &d)
}

// setupMacvlans creates macvlan sub-interfaces based on the configuration.
func (mgr *MacvlanManager) setupMacvlans(ifaces []v2alpha1.MacvlanDeviceConfig) error {
	if len(ifaces) == 0 {
		// nothing to do. early exit.
		return nil
	}

	links, err := mgr.netlinkLinkLister()
	if err != nil {
		return err
	}

	// Build a map of existing links
	linkMap := make(map[string]netlink.Link)
	for _, link := range links {
		linkMap[link.Attrs().Name] = link
	}

	var errs error

	for _, iface := range ifaces {
		// Find parent interface
		parentLink, ok := linkMap[iface.ParentIfName]
		if !ok {
			errs = errors.Join(errs, fmt.Errorf("parent interface %s not found: %w", iface.ParentIfName, errInterfaceNotFound))
			continue
		}

		var mode netlink.MacvlanMode

		switch iface.Mode {
		case "private":
			mode = netlink.MACVLAN_MODE_PRIVATE
		case "vepa":
			mode = netlink.MACVLAN_MODE_VEPA
		case "bridge":
			mode = netlink.MACVLAN_MODE_BRIDGE
		case "passthru":
			mode = netlink.MACVLAN_MODE_PASSTHRU
		case "source":
			mode = netlink.MACVLAN_MODE_SOURCE
		default:
			errs = errors.Join(errs, fmt.Errorf("unknown macvlan mode: %s for %s", iface.Mode, iface.ParentIfName))
			continue
		}

		// Create sub-interfaces
		for i := 0; i < iface.Count; i++ {
			subIfName := fmt.Sprintf("%s.%d", iface.ParentIfName, i)

			// Check if interface already exists
			if _, exists := linkMap[subIfName]; exists {
				mgr.logger.Debug(
					"macvlan sub-interface already exists, skipping",
					logfields.Interface, subIfName,
				)
				continue
			}

			// Create macvlan link
			macvlan := &netlink.Macvlan{
				LinkAttrs: netlink.LinkAttrs{
					Name:        subIfName,
					ParentIndex: parentLink.Attrs().Index,
				},
				Mode: mode,
			}

			if err := netlink.LinkAdd(macvlan); err != nil {
				errs = errors.Join(errs, fmt.Errorf(
					"failed to create macvlan sub-interface %s: %w",
					subIfName, err,
				))
				continue
			}

			// Bring the interface up
			if err := netlink.LinkSetUp(macvlan); err != nil {
				errs = errors.Join(errs, fmt.Errorf(
					"failed to bring up macvlan sub-interface %s: %w",
					subIfName, err,
				))
				// Don't continue here - the interface was created
			}

			mgr.logger.Info(
				"created macvlan sub-interface",
				logfields.Interface, subIfName,
				logfields.Mode, macvlanModeToString(mode),
			)
		}

		mgr.logger.Info(
			"macvlan configuration complete",
			logfields.Interface, iface.ParentIfName,
			logfields.Count, iface.Count,
		)
	}

	return errs
}

// macvlanModeToString converts a netlink.MacvlanMode to a string.
func macvlanModeToString(mode netlink.MacvlanMode) string {
	switch mode {
	case netlink.MACVLAN_MODE_PRIVATE:
		return "private"
	case netlink.MACVLAN_MODE_VEPA:
		return "vepa"
	case netlink.MACVLAN_MODE_BRIDGE:
		return "bridge"
	case netlink.MACVLAN_MODE_PASSTHRU:
		return "passthru"
	case netlink.MACVLAN_MODE_SOURCE:
		return "source"
	default:
		return "unknown(" + strconv.Itoa(int(mode)) + ")"
	}
}
