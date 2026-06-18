// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package macvlan

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

var (
	errInterfaceNotFound = errors.New("interface not found")
	errNotAMacvlan       = errors.New("interface is not a macvlan device")
)

// netlink seams. Setup and Free are value-receiver methods on MacvlanDevice and
// therefore cannot reach the manager's injected funcs, so the primitives they
// need live as package-level vars that tests can override.
var (
	netlinkLinkByName = safenetlink.LinkByName
	netlinkLinkAdd    = netlink.LinkAdd
	netlinkLinkDel    = netlink.LinkDel
)

type MacvlanManager struct {
	logger            *slog.Logger
	config            *v2alpha1.MacvlanDeviceManagerConfig
	netlinkLinkLister func() ([]netlink.Link, error)
}

func (m *MacvlanManager) init() error {
	m.logger.Debug(
		"initializing macvlan device manager",
	)

	// macvlan sub-interfaces are created on demand in Device.Setup, not at
	// startup. Validate the configuration here so misconfiguration fails fast
	// instead of surfacing only when the first pod is scheduled.
	return m.validateConfig(m.config.Ifaces)
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

// ListDevices advertises the macvlan devices derived from configuration.
//
// Unlike sr-iov or dummy, macvlan sub-interfaces are virtual devices that this
// driver owns: they do not exist in the kernel until a claim is allocated and
// Device.Setup creates one. ListDevices therefore does not scan the kernel; it
// synthesises Count discrete devices per configured parent interface so DRA can
// advertise and allocate them. The (Count+1)th claim stays Pending.
func (mgr *MacvlanManager) ListDevices() ([]types.Device, error) {
	var result []types.Device

	for _, iface := range mgr.config.Ifaces {
		mode, err := parseMacvlanMode(iface.Mode)
		if err != nil {
			return nil, fmt.Errorf("invalid macvlan mode for parent %s: %w", iface.ParentIfName, err)
		}

		for i := 0; i < iface.Count; i++ {
			// kernel name uses dot notation (eth0.0); the DRA device name uses
			// dash notation (eth0-0) to satisfy DRA device-name constraints.
			kernelName := fmt.Sprintf("%s.%d", iface.ParentIfName, i)

			result = append(result, &MacvlanDevice{
				Name:            strings.ReplaceAll(kernelName, ".", "-"),
				ParentName:      iface.ParentIfName,
				KernelIfaceName: kernelName,
				Mode:            mode,
			})
		}
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
	Mode            netlink.MacvlanMode
}

func (d MacvlanDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	result := make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
	result[types.IfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.IfName())}
	result[types.KernelIfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.KernelIfName())}
	result[types.ParentIfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.ParentName)}
	result[types.MacVlanModeLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(macvlanModeToString(d.Mode))}

	return result
}

// Setup creates the macvlan sub-interface in the root network namespace. The
// caller (RunPodSandbox) subsequently moves it into the pod netns.
//
// netlink.LinkAdd uses NLM_F_EXCL and is therefore not idempotent: it returns
// EEXIST if the interface already exists. On EEXIST we adopt the existing
// device when its mode and parent match the requested config (e.g. a leftover
// from a prior, partially-completed allocation), otherwise we delete and
// recreate it so we never adopt a stale device with the wrong configuration.
func (d MacvlanDevice) Setup(cfg types.DeviceConfig) error {
	parent, err := netlinkLinkByName(d.ParentName)
	if err != nil {
		return fmt.Errorf("failed to find parent interface %s: %w", d.ParentName, err)
	}

	macvlan := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        d.KernelIfaceName,
			ParentIndex: parent.Attrs().Index,
		},
		Mode: d.Mode,
	}

	err = netlinkLinkAdd(macvlan)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("failed to create macvlan interface %s: %w", d.KernelIfaceName, err)
	}

	// The interface already exists. Adopt it if it matches our config,
	// otherwise replace it.
	existing, lookupErr := netlinkLinkByName(d.KernelIfaceName)
	if lookupErr != nil {
		return fmt.Errorf("macvlan interface %s exists but could not be read: %w", d.KernelIfaceName, lookupErr)
	}

	existingMacvlan, ok := existing.(*netlink.Macvlan)
	if ok &&
		existingMacvlan.Mode == d.Mode &&
		existing.Attrs().ParentIndex == parent.Attrs().Index {
		// Same configuration; adopt the existing device.
		return nil
	}

	// Stale or mismatched device. Delete and recreate it.
	if delErr := netlinkLinkDel(existing); delErr != nil {
		return fmt.Errorf("failed to delete stale macvlan interface %s: %w", d.KernelIfaceName, delErr)
	}
	if addErr := netlinkLinkAdd(macvlan); addErr != nil {
		return fmt.Errorf("failed to recreate macvlan interface %s: %w", d.KernelIfaceName, addErr)
	}

	return nil
}

// Free deletes the macvlan sub-interface. This is best-effort cleanup for a
// device that was created by Setup but never attached to a pod (e.g. the pod
// failed to start after prepare): once the interface is moved into a pod netns
// and that netns is reaped, the kernel destroys the macvlan automatically, so
// the root-namespace lookup here simply finds nothing and returns nil.
func (d MacvlanDevice) Free(cfg types.DeviceConfig) error {
	l, err := netlinkLinkByName(d.KernelIfaceName)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			// Already gone (moved into a pod netns that was reaped, or never
			// created). Nothing to do.
			return nil
		}
		return fmt.Errorf("failed to find macvlan interface %s: %w", d.KernelIfaceName, err)
	}

	if _, ok := l.(*netlink.Macvlan); !ok {
		// Not a macvlan; refuse to touch an interface we do not own.
		return fmt.Errorf("%w: %s", errNotAMacvlan, d.KernelIfaceName)
	}

	if err := netlinkLinkDel(l); err != nil {
		return fmt.Errorf("failed to delete macvlan interface %s: %w", d.KernelIfaceName, err)
	}

	return nil
}

func (d MacvlanDevice) Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool {
	if len(filter.DeviceManagers) != 0 && !slices.Contains(filter.DeviceManagers, types.DeviceManagerTypeMacvlan.String()) {
		return false
	}

	// Macvlan devices have no PCI address, vendor/device ID, or kernel driver
	// binding. A filter specifying any of these fields cannot match a macvlan device.
	if len(filter.PCIAddrs) != 0 || len(filter.VendorIDs) != 0 ||
		len(filter.DeviceIDs) != 0 || len(filter.Drivers) != 0 {
		return false
	}

	// ifNames are compared after normalising dots to dashes, because macvlan
	// kernel names (e.g. "eth0.0") are stored with dots replaced by dashes
	// ("eth0-0") to satisfy DRA device-name constraints. Users may write either
	// form in the filter.
	if len(filter.IfNames) != 0 {
		matched := false
		for _, name := range filter.IfNames {
			if strings.ReplaceAll(name, ".", "-") == d.IfName() {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(filter.ParentIfNames) != 0 && !slices.Contains(filter.ParentIfNames, d.ParentName) {
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

// validateConfig checks, at startup, that every configured parent interface
// exists and every mode is parseable. It creates nothing.
func (mgr *MacvlanManager) validateConfig(ifaces []v2alpha1.MacvlanDeviceConfig) error {
	if len(ifaces) == 0 {
		// nothing to do. early exit.
		return nil
	}

	links, err := mgr.netlinkLinkLister()
	if err != nil {
		return err
	}

	existing := make(map[string]bool, len(links))
	for _, link := range links {
		existing[link.Attrs().Name] = true
	}

	var errs error
	for _, iface := range ifaces {
		if !existing[iface.ParentIfName] {
			errs = errors.Join(errs, fmt.Errorf("parent interface %s not found: %w", iface.ParentIfName, errInterfaceNotFound))
		}
		if _, err := parseMacvlanMode(iface.Mode); err != nil {
			errs = errors.Join(errs, fmt.Errorf("parent interface %s: %w", iface.ParentIfName, err))
		}
	}

	return errs
}

// parseMacvlanMode converts a macvlan mode string to a netlink.MacvlanMode. An
// empty string maps to bridge mode, matching the CRD default.
func parseMacvlanMode(mode string) (netlink.MacvlanMode, error) {
	switch mode {
	case "", "bridge":
		return netlink.MACVLAN_MODE_BRIDGE, nil
	case "private":
		return netlink.MACVLAN_MODE_PRIVATE, nil
	case "vepa":
		return netlink.MACVLAN_MODE_VEPA, nil
	case "passthru":
		return netlink.MACVLAN_MODE_PASSTHRU, nil
	case "source":
		return netlink.MACVLAN_MODE_SOURCE, nil
	default:
		return 0, fmt.Errorf("unknown macvlan mode: %q", mode)
	}
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
