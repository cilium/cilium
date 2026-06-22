// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dummy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

var (
	errNotADummy     = errors.New("interface is not a dummy device")
	errNegativeCount = errors.New("dummy device count must not be negative")
)

// dummyIfNamePrefix is the fixed prefix for synthesised dummy link names. The
// manager advertises Count devices named dummy0..dummy<Count-1>.
const dummyIfNamePrefix = "dummy"

// netlink seams. Setup and Free are value-receiver methods on DummyDevice and
// therefore cannot reach the manager's state, so the primitives they need live
// as package-level vars that tests can override.
var (
	netlinkLinkByName = safenetlink.LinkByName
	netlinkLinkAdd    = netlink.LinkAdd
	netlinkLinkDel    = netlink.LinkDel
)

type DummyManager struct {
	logger *slog.Logger
	config *v2alpha1.DummyDeviceManagerConfig
}

func (m *DummyManager) init() error {
	m.logger.Debug("initializing dummy device manager")

	// Dummy links are created on demand in Device.Setup, not at startup.
	// Validate the configuration here so misconfiguration fails fast instead of
	// surfacing only when the first pod is scheduled.
	return validateConfig(m.config.Count)
}

func NewManager(logger *slog.Logger, cfg *v2alpha1.DummyDeviceManagerConfig) (*DummyManager, error) {
	mgr := &DummyManager{
		logger: logger,
		config: cfg,
	}

	return mgr, mgr.init()
}

func (mgr *DummyManager) Type() types.DeviceManagerType {
	return types.DeviceManagerTypeDummy
}

// ListDevices advertises the dummy devices derived from configuration.
//
// Like macvlan, dummy links are virtual devices that this driver owns: they do
// not exist in the kernel until a claim is allocated and Device.Setup creates
// one. ListDevices therefore does not scan the kernel; it synthesises Count
// discrete devices named dummy0..dummy<Count-1> so DRA can advertise and
// allocate them. The (Count+1)th claim stays Pending.
func (mgr *DummyManager) ListDevices() ([]types.Device, error) {
	var result []types.Device

	for i := 0; i < mgr.config.Count; i++ {
		result = append(result, &DummyDevice{
			Name: fmt.Sprintf("%s%d", dummyIfNamePrefix, i),
		})
	}

	return result, nil
}

func (mgr *DummyManager) RestoreDevice(data []byte) (types.Device, error) {
	var dev DummyDevice
	if err := dev.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &dev, nil
}

type DummyDevice struct {
	Name   string
	HWAddr string
	MTU    int
	Flags  string
}

func (d DummyDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	result := make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
	result[types.IfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.IfName())}
	result[types.KernelIfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.KernelIfName())}

	return result
}

// Setup creates the dummy link in the root network namespace. The caller
// (RunPodSandbox) subsequently moves it into the pod netns.
//
// netlink.LinkAdd uses NLM_F_EXCL and is therefore not idempotent: it returns
// EEXIST if the interface already exists. On EEXIST we adopt the existing device
// when it is a dummy (e.g. a leftover from a prior, partially-completed
// allocation), otherwise we delete and recreate it so we never adopt a stale
// device of the wrong type.
func (d DummyDevice) Setup(cfg types.DeviceConfig) error {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: d.Name},
	}

	err := netlinkLinkAdd(dummy)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("failed to create dummy interface %s: %w", d.Name, err)
	}

	// The interface already exists. Adopt it if it is a dummy, otherwise
	// replace it.
	existing, lookupErr := netlinkLinkByName(d.Name)
	if lookupErr != nil {
		return fmt.Errorf("dummy interface %s exists but could not be read: %w", d.Name, lookupErr)
	}

	if _, ok := existing.(*netlink.Dummy); ok {
		// Same type; adopt the existing device.
		return nil
	}

	// Stale or mismatched device. Delete and recreate it.
	if delErr := netlinkLinkDel(existing); delErr != nil {
		return fmt.Errorf("failed to delete stale dummy interface %s: %w", d.Name, delErr)
	}
	if addErr := netlinkLinkAdd(dummy); addErr != nil {
		return fmt.Errorf("failed to recreate dummy interface %s: %w", d.Name, addErr)
	}

	return nil
}

// Free deletes the dummy link. This is best-effort cleanup for a device that was
// created by Setup but never attached to a pod (e.g. the pod failed to start
// after prepare): once the interface is moved into a pod netns and that netns is
// reaped, the kernel destroys the dummy automatically, so the root-namespace
// lookup here simply finds nothing and returns nil.
func (d DummyDevice) Free(cfg types.DeviceConfig) error {
	l, err := netlinkLinkByName(d.Name)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			// Already gone (moved into a pod netns that was reaped, or never
			// created). Nothing to do.
			return nil
		}
		return fmt.Errorf("failed to find dummy interface %s: %w", d.Name, err)
	}

	if _, ok := l.(*netlink.Dummy); !ok {
		// Not a dummy; refuse to touch an interface we do not own.
		return fmt.Errorf("%w: %s", errNotADummy, d.Name)
	}

	if err := netlinkLinkDel(l); err != nil {
		return fmt.Errorf("failed to delete dummy interface %s: %w", d.Name, err)
	}

	return nil
}

func (d DummyDevice) Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool {
	if len(filter.DeviceManagers) != 0 && !slices.Contains(filter.DeviceManagers, types.DeviceManagerTypeDummy.String()) {
		return false
	}

	// Dummy devices have no parent, PCI address, vendor/device ID, or kernel
	// driver binding. A filter that specifies any of these fields cannot match
	// a dummy device.
	if len(filter.ParentIfNames) != 0 || len(filter.PCIAddrs) != 0 ||
		len(filter.VendorIDs) != 0 || len(filter.DeviceIDs) != 0 ||
		len(filter.Drivers) != 0 {
		return false
	}

	if len(filter.IfNames) != 0 && !slices.Contains(filter.IfNames, d.IfName()) {
		return false
	}

	return true
}

func (d DummyDevice) IfName() string {
	return d.Name
}

func (d DummyDevice) KernelIfName() string {
	return d.Name
}

func (d DummyDevice) MarshalBinary() (data []byte, err error) {
	return json.Marshal(d)
}

func (d *DummyDevice) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, &d)
}

// validateConfig checks, at startup, that the configured dummy device count is
// not negative. It creates nothing.
func validateConfig(count int) error {
	if count < 0 {
		return fmt.Errorf("%w: %d", errNegativeCount, count)
	}
	return nil
}
