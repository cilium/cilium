// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const (
	defaultReservedRXQueues = 1
	mainRSSContext          = 0
	firstLeasedRXQueueID    = 1

	activeRXQueuesLogField      = "activeRxQueues"
	reservedRXQueuesLogField    = "reservedRxQueues"
	rssUpdatedLogField          = "rssUpdated"
	tcpDataSplitUpdatedLogField = "tcpDataSplitUpdated"
)

var (
	errNoInterfaces         = errors.New("no RX queue interfaces configured")
	errDuplicateInterface   = errors.New("duplicate RX queue interface")
	errInsufficientRXQueues = errors.New("insufficient RX queues")
	errNoAvailableRXQueue   = errors.New("no reserved RX queue is available")
	errInvalidAllocation    = errors.New("invalid RX queue allocation")
	errActiveLease          = errors.New("RX queue lease is still active")

	netlinkLinkByName     = safenetlink.LinkByName
	netlinkNetDevQueueGet = netlink.NetDevQueueGet
	netlinkNetDevRSSGet   = netlink.NetDevRSSGet
	netlinkNetDevRSSSet   = netlink.NetDevRSSSet
	netlinkNetDevRingsGet = netlink.NetDevRingsGet
	netlinkNetDevRingsSet = netlink.NetDevRingsSet
)

type RXQueueManager struct {
	devices      []*RXQueueDevice
	reservations map[string]*queueReservations
	mu           lock.Mutex
}

func NewManager(logger *slog.Logger, cfg *v2alpha1.RXQueueDeviceManagerConfig) (*RXQueueManager, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	mgr := &RXQueueManager{reservations: make(map[string]*queueReservations)}
	var programmed []*rxQueueNICState
	for _, iface := range cfg.Ifaces {
		count := iface.Count
		if count == 0 {
			count = defaultReservedRXQueues
		}

		dev, err := discoverDevice(iface.IfName, count)
		if err != nil {
			return nil, rollbackRXQueueNICs(programmed, err)
		}
		dev.reservations = mgr.reservationsFor(dev.PhysicalIfName)
		state, err := prepareRXQueueNIC(dev)
		if err != nil {
			return nil, rollbackRXQueueNICs(programmed, err)
		}
		programmed = append(programmed, state)
		mgr.devices = append(mgr.devices, dev)

		logger.Debug("prepared RX queues for leasing",
			logfields.Device, iface.IfName,
			activeRXQueuesLogField, dev.TotalRXQueues,
			reservedRXQueuesLogField, dev.ReservedQueueIDs,
			rssUpdatedLogField, state.rssChanged,
			tcpDataSplitUpdatedLogField, state.ringsChanged,
		)
	}

	return mgr, nil
}

type rxQueueNICState struct {
	ifName        string
	ifIndex       int
	originalRSS   *netlink.NetDevRSS
	originalRings netlink.NetDevRings
	rssChanged    bool
	ringsChanged  bool
}

func prepareRXQueueNIC(dev *RXQueueDevice) (_ *rxQueueNICState, retErr error) {
	link, err := netlinkLinkByName(dev.PhysicalIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to find RX queue interface %s: %w", dev.PhysicalIfName, err)
	}

	rss, err := netlinkNetDevRSSGet(link.Attrs().Index, mainRSSContext)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSS configuration on %s: %w", dev.PhysicalIfName, err)
	}
	if rss == nil {
		return nil, fmt.Errorf("failed to read RSS configuration on %s: empty response", dev.PhysicalIfName)
	}
	desiredTable, err := rssTableWithoutReservedQueues(rss.IndirectionTable, dev.TotalRXQueues, dev.ReservedQueueIDs)
	if err != nil {
		return nil, fmt.Errorf("invalid RSS configuration on %s: %w", dev.PhysicalIfName, err)
	}

	rings, err := netlinkNetDevRingsGet(link.Attrs().Index)
	if err != nil {
		return nil, fmt.Errorf("failed to read ring configuration on %s: %w", dev.PhysicalIfName, err)
	}
	if rings == nil {
		return nil, fmt.Errorf("failed to read ring configuration on %s: empty response", dev.PhysicalIfName)
	}

	state := &rxQueueNICState{
		ifName:        dev.PhysicalIfName,
		ifIndex:       link.Attrs().Index,
		originalRSS:   cloneNetDevRSS(rss),
		originalRings: *rings,
	}
	defer func() {
		if retErr == nil {
			return
		}
		if err := state.restore(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to roll back NIC configuration on %s: %w", state.ifName, err))
		}
	}()

	expectedRSS := cloneNetDevRSS(rss)
	expectedRSS.IndirectionTable = desiredTable
	if !slices.Equal(rss.IndirectionTable, desiredTable) {
		if err := netlinkNetDevRSSSet(state.ifIndex, mainRSSContext, netlink.NetDevRSSConfig{IndirectionTable: desiredTable}); err != nil {
			return nil, fmt.Errorf("failed to exclude reserved queues from RSS on %s: %w", state.ifName, err)
		}
		state.rssChanged = true
	}

	// io_uring zero-copy receive requires TCP header/data splitting with a
	// zero split threshold. Drivers that do not report their split setting
	// read back as unknown, so attempt the change and let the driver decide.
	expectedRings := *rings
	expectedRings.TCPDataSplit = netlink.NetDevTCPDataSplitEnabled
	expectedRings.HDSThreshold = 0
	if rings.TCPDataSplit != expectedRings.TCPDataSplit || rings.HDSThreshold != expectedRings.HDSThreshold {
		config := netlink.NetDevRingsConfig{
			TCPDataSplit: &expectedRings.TCPDataSplit,
			HDSThreshold: &expectedRings.HDSThreshold,
		}
		if err := netlinkNetDevRingsSet(state.ifIndex, config); err != nil {
			return nil, fmt.Errorf("failed to enable TCP data splitting on %s: %w", state.ifName, err)
		}
		state.ringsChanged = true
	}

	if err := verifyRXQueueNIC(state.ifName, state.ifIndex, expectedRSS, &expectedRings); err != nil {
		return nil, err
	}

	return state, nil
}

func rssTableWithoutReservedQueues(table []uint32, total int, reserved []uint32) ([]uint32, error) {
	if len(table) == 0 {
		return nil, errors.New("RSS indirection table is empty")
	}
	if total <= 0 {
		return nil, errors.New("no active RX queues")
	}

	reservedSet := make(map[uint32]struct{}, len(reserved))
	for _, queueID := range reserved {
		if uint64(queueID) >= uint64(total) {
			return nil, fmt.Errorf("reserved queue %d exceeds the %d active RX queues", queueID, total)
		}
		if _, exists := reservedSet[queueID]; exists {
			return nil, fmt.Errorf("reserved queue %d is duplicated", queueID)
		}
		reservedSet[queueID] = struct{}{}
	}

	allowed := make([]uint32, 0, total-len(reservedSet))
	counts := make([]int, total)
	for queueID := range total {
		if _, reserved := reservedSet[uint32(queueID)]; !reserved {
			allowed = append(allowed, uint32(queueID))
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("no RX queue remains available for RSS")
	}

	result := slices.Clone(table)
	for _, queueID := range table {
		if uint64(queueID) >= uint64(total) {
			return nil, fmt.Errorf("indirection table references queue %d, but only %d RX queues are active", queueID, total)
		}
		if _, reserved := reservedSet[queueID]; !reserved {
			counts[queueID]++
		}
	}

	// Keep queues excluded by the existing RSS policy excluded.
	candidates := make([]uint32, 0, len(allowed))
	for _, queueID := range allowed {
		if counts[queueID] != 0 {
			candidates = append(candidates, queueID)
		}
	}
	if len(candidates) == 0 {
		candidates = allowed
	}

	for i, queueID := range result {
		if _, reserved := reservedSet[queueID]; !reserved {
			continue
		}

		replacement := candidates[0]
		for _, candidate := range candidates[1:] {
			if counts[candidate] < counts[replacement] {
				replacement = candidate
			}
		}
		result[i] = replacement
		counts[replacement]++
	}

	return result, nil
}

func cloneNetDevRSS(rss *netlink.NetDevRSS) *netlink.NetDevRSS {
	if rss == nil {
		return nil
	}
	clone := *rss
	clone.IndirectionTable = slices.Clone(rss.IndirectionTable)
	clone.HashKey = slices.Clone(rss.HashKey)
	return &clone
}

func equalNetDevRSS(a, b *netlink.NetDevRSS) bool {
	return a != nil && b != nil &&
		a.Context == b.Context &&
		a.HashFunction == b.HashFunction &&
		slices.Equal(a.IndirectionTable, b.IndirectionTable) &&
		slices.Equal(a.HashKey, b.HashKey) &&
		a.InputTransformation == b.InputTransformation
}

func verifyRXQueueNIC(ifName string, ifIndex int, wantRSS *netlink.NetDevRSS, wantRings *netlink.NetDevRings) error {
	rss, err := netlinkNetDevRSSGet(ifIndex, mainRSSContext)
	if err != nil {
		return fmt.Errorf("failed to verify RSS configuration on %s: %w", ifName, err)
	}
	if !equalNetDevRSS(rss, wantRSS) {
		return fmt.Errorf("RSS configuration read back incorrectly on %s", ifName)
	}

	rings, err := netlinkNetDevRingsGet(ifIndex)
	if err != nil {
		return fmt.Errorf("failed to verify ring configuration on %s: %w", ifName, err)
	}
	if rings == nil || *rings != *wantRings {
		return fmt.Errorf("ring configuration read back incorrectly on %s", ifName)
	}

	return nil
}

func (s *rxQueueNICState) restore() error {
	var errs []error
	if s.ringsChanged {
		if err := netlinkNetDevRingsSet(s.ifIndex, netlink.NetDevRingsConfig{
			TCPDataSplit: &s.originalRings.TCPDataSplit,
			HDSThreshold: &s.originalRings.HDSThreshold,
		}); err != nil {
			errs = append(errs, fmt.Errorf("restore ring configuration: %w", err))
		} else {
			rings, err := netlinkNetDevRingsGet(s.ifIndex)
			if err != nil {
				errs = append(errs, fmt.Errorf("verify restored ring configuration: %w", err))
			} else if rings == nil || *rings != s.originalRings {
				errs = append(errs, errors.New("restored ring configuration did not match its original state"))
			}
		}
	}
	if s.rssChanged {
		if err := netlinkNetDevRSSSet(s.ifIndex, mainRSSContext, netlink.NetDevRSSConfig{IndirectionTable: s.originalRSS.IndirectionTable}); err != nil {
			errs = append(errs, fmt.Errorf("restore RSS configuration: %w", err))
		} else {
			rss, err := netlinkNetDevRSSGet(s.ifIndex, mainRSSContext)
			if err != nil {
				errs = append(errs, fmt.Errorf("verify restored RSS configuration: %w", err))
			} else if !equalNetDevRSS(rss, s.originalRSS) {
				errs = append(errs, errors.New("restored RSS configuration did not match its original state"))
			}
		}
	}
	return errors.Join(errs...)
}

func rollbackRXQueueNICs(states []*rxQueueNICState, cause error) error {
	for _, state := range slices.Backward(states) {
		if err := state.restore(); err != nil {
			cause = errors.Join(cause, fmt.Errorf("failed to roll back NIC configuration on %s: %w", state.ifName, err))
		}
	}
	return cause
}

func validateConfig(cfg *v2alpha1.RXQueueDeviceManagerConfig) error {
	if cfg == nil || len(cfg.Ifaces) == 0 {
		return errNoInterfaces
	}

	seen := make(map[string]struct{}, len(cfg.Ifaces))
	for _, iface := range cfg.Ifaces {
		if iface.IfName == "" {
			return errors.New("RX queue interface name is empty")
		}
		if err := types.ValidateInterfaceName(iface.IfName); err != nil {
			return fmt.Errorf("invalid RX queue interface %q: %w", iface.IfName, err)
		}
		if iface.Count < 0 {
			return fmt.Errorf("RX queue count for %s must be positive", iface.IfName)
		}
		if _, exists := seen[iface.IfName]; exists {
			return fmt.Errorf("%w: %s", errDuplicateInterface, iface.IfName)
		}
		seen[iface.IfName] = struct{}{}
	}

	return nil
}

func (m *RXQueueManager) Type() types.DeviceManagerType {
	return types.DeviceManagerTypeRXQueue
}

func (m *RXQueueManager) Run(ctx context.Context, publish func([]types.Device)) error {
	devices := make([]types.Device, 0, len(m.devices))
	for _, dev := range m.devices {
		devices = append(devices, dev)
	}
	publish(devices)
	<-ctx.Done()
	return nil
}

func (m *RXQueueManager) RestoreDevice(data []byte) (types.Device, error) {
	dev := &RXQueueDevice{}
	if err := dev.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	dev.reservations = m.reservationsFor(dev.PhysicalIfName)
	if err := dev.restoreReservation(); err != nil {
		return nil, err
	}
	return dev, nil
}

func discoverDevice(ifName string, reserved int) (*RXQueueDevice, error) {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to find RX queue interface %s: %w", ifName, err)
	}

	total, err := activeRXQueueCount(link)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect RX queues on %s: %w", ifName, err)
	}
	if total <= reserved {
		return nil, fmt.Errorf("%w: %s has %d active RX queues; reserving %d would leave none for normal receive processing",
			errInsufficientRXQueues, ifName, total, reserved)
	}

	hwAddr := ""
	if link.Attrs().HardwareAddr != nil {
		hwAddr = link.Attrs().HardwareAddr.String()
	}

	return &RXQueueDevice{
		PhysicalIfName:   ifName,
		HardwareAddress:  hwAddr,
		MTU:              link.Attrs().MTU,
		TotalRXQueues:    total,
		ReservedQueueIDs: reservedRXQueueIDs(total, reserved),
	}, nil
}

func activeRXQueueCount(link netlink.Link) (int, error) {
	attrs := link.Attrs()
	if attrs.Flags&net.FlagUp == 0 {
		return 0, errors.New("interface is down")
	}
	if attrs.NumRxQueues <= 0 {
		return 0, errors.New("interface reports no RX queues")
	}

	for queueID := 0; queueID < attrs.NumRxQueues; queueID++ {
		_, err := netlinkNetDevQueueGet(attrs.Index, uint32(queueID), netlink.NetDevQueueTypeRx)
		if err == nil {
			continue
		}
		if errors.Is(err, unix.EINVAL) {
			return queueID, nil
		}
		return 0, fmt.Errorf("queue-get for queue %d: %w", queueID, err)
	}

	return attrs.NumRxQueues, nil
}

func reservedRXQueueIDs(total, count int) []uint32 {
	if count <= 0 || total <= count {
		return nil
	}

	queues := make([]uint32, 0, count)
	for i := range count {
		queues = append(queues, uint32(total-1-i))
	}
	return queues
}

type RXQueueDevice struct {
	PhysicalIfName   string   `json:"physicalIfName"`
	HardwareAddress  string   `json:"hardwareAddress,omitempty"`
	MTU              int      `json:"mtu,omitempty"`
	TotalRXQueues    int      `json:"totalRXQueues"`
	ReservedQueueIDs []uint32 `json:"reservedQueueIDs"`

	Prepared        bool           `json:"prepared,omitempty"`
	ShareID         kube_types.UID `json:"shareID,omitempty"`
	PodIfName       string         `json:"podIfName,omitempty"`
	PhysicalQueueID uint32         `json:"physicalQueueID,omitempty"`
	VirtualQueueID  uint32         `json:"virtualQueueID,omitempty"`
	reservations    *queueReservations

	mu lock.Mutex
}

func (d *RXQueueDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	attrs := map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
		types.IfNameLabel:        {StringValue: ptr.To(d.PhysicalIfName)},
		types.KernelIfNameLabel:  {StringValue: ptr.To(d.PhysicalIfName)},
		types.DeviceManagerLabel: {StringValue: ptr.To(types.DeviceManagerTypeRXQueue.String())},
	}
	if d.HardwareAddress != "" {
		attrs[types.HWAddrLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.HardwareAddress)}
	}
	if d.Prepared {
		virtualQueueID := int64(d.VirtualQueueID)
		attrs[types.RXQueueIDLabel] = resourceapi.DeviceAttribute{IntValue: &virtualQueueID}
	}
	return attrs
}

func (d *RXQueueDevice) GetCapacity() map[resourceapi.QualifiedName]resourceapi.DeviceCapacity {
	one := apiresource.MustParse("1")
	capacity := *apiresource.NewQuantity(int64(len(d.ReservedQueueIDs)), apiresource.DecimalSI)

	return map[resourceapi.QualifiedName]resourceapi.DeviceCapacity{
		types.RXQueuesCapacity: {
			Value: capacity,
			RequestPolicy: &resourceapi.CapacityRequestPolicy{
				Default:     ptr.To(one),
				ValidValues: []apiresource.Quantity{one},
			},
		},
	}
}

func (d *RXQueueDevice) AllowMultipleAllocations() bool {
	return true
}

func (d *RXQueueDevice) Setup(allocation types.DeviceAllocation) (types.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.reserve(allocation, d.ReservedQueueIDs)
}

func (d *RXQueueDevice) Recover(allocation types.DeviceAllocation) (types.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.Prepared || d.ShareID != allocation.ShareID {
		return nil, fmt.Errorf("%w: stored RX queue state does not match allocation", errInvalidAllocation)
	}
	podIfName := allocation.Config.PodIfName
	if podIfName == "" {
		podIfName = types.DefaultRXQueuePodIfName
	}
	if d.PodIfName != podIfName {
		return nil, fmt.Errorf("%w: stored RX queue state does not match allocation", errInvalidAllocation)
	}
	if err := validateAllocation(allocation); err != nil {
		return nil, err
	}
	if !slices.Contains(d.ReservedQueueIDs, d.PhysicalQueueID) {
		return nil, fmt.Errorf("%w: stored RX queue %d is not reserved", errInvalidAllocation, d.PhysicalQueueID)
	}
	if err := d.restoreReservation(); err != nil {
		return nil, err
	}
	return d.clone(), nil
}

func validateAllocation(allocation types.DeviceAllocation) error {
	if allocation.ShareID == "" {
		return fmt.Errorf("%w: share ID is required", errInvalidAllocation)
	}

	requested, exists := allocation.ConsumedCapacity[types.RXQueuesCapacity]
	if !exists {
		return fmt.Errorf("%w: consumed %s capacity is required",
			errInvalidAllocation, types.RXQueuesCapacity)
	}
	one := apiresource.MustParse("1")
	if requested.Cmp(one) != 0 {
		return fmt.Errorf("%w: %s must consume exactly one RX queue, got %s",
			errInvalidAllocation, types.RXQueuesCapacity, requested.String())
	}

	return nil
}

func netlinkNetDevQueueGetByName(ifName string, queueID uint32) (*netlink.NetDevQueue, error) {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to find physical interface %s: %w", ifName, err)
	}
	queue, err := netlinkNetDevQueueGet(link.Attrs().Index, queueID, netlink.NetDevQueueTypeRx)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect RX queue %s/%d: %w", ifName, queueID, err)
	}
	return queue, nil
}

func (d *RXQueueDevice) Free(allocation types.DeviceAllocation) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.Prepared {
		return nil
	}
	if err := validateAllocation(allocation); err != nil {
		return err
	}
	if d.ShareID != allocation.ShareID {
		return fmt.Errorf("%w: stored RX queue state does not match allocation", errInvalidAllocation)
	}

	queue, err := netlinkNetDevQueueGetByName(d.PhysicalIfName, d.PhysicalQueueID)
	if err != nil {
		return err
	}
	if queue.Lease != nil {
		return fmt.Errorf("%w: %s/%d", errActiveLease, d.PhysicalIfName, d.PhysicalQueueID)
	}

	d.releaseReservation()
	return nil
}

func (d *RXQueueDevice) Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool {
	if len(filter.DeviceManagers) != 0 &&
		!slices.Contains(filter.DeviceManagers, types.DeviceManagerTypeRXQueue.String()) {
		return false
	}
	if len(filter.IfNames) != 0 && !slices.Contains(filter.IfNames, d.PhysicalIfName) {
		return false
	}

	return len(filter.PFNames) == 0 &&
		len(filter.ParentIfNames) == 0 &&
		len(filter.PCIAddrs) == 0 &&
		len(filter.VendorIDs) == 0 &&
		len(filter.DeviceIDs) == 0 &&
		len(filter.Drivers) == 0
}

func (d *RXQueueDevice) IfName() string {
	if d.Prepared {
		return d.PodIfName
	}
	return d.PhysicalIfName
}

func (d *RXQueueDevice) KernelIfName() string {
	return d.IfName()
}

// Merge is a no-op because RX queue inventory is derived entirely from the
// current physical interface. Allocation-specific state lives separately.
func (d *RXQueueDevice) Merge(_ types.Device) {}

type deviceState struct {
	PhysicalIfName   string         `json:"physicalIfName"`
	HardwareAddress  string         `json:"hardwareAddress,omitempty"`
	MTU              int            `json:"mtu,omitempty"`
	TotalRXQueues    int            `json:"totalRXQueues"`
	ReservedQueueIDs []uint32       `json:"reservedQueueIDs"`
	Prepared         bool           `json:"prepared,omitempty"`
	ShareID          kube_types.UID `json:"shareID,omitempty"`
	PodIfName        string         `json:"podIfName,omitempty"`
	PhysicalQueueID  uint32         `json:"physicalQueueID,omitempty"`
	VirtualQueueID   uint32         `json:"virtualQueueID,omitempty"`
}

func (d *RXQueueDevice) MarshalBinary() ([]byte, error) {
	return json.Marshal(deviceState{
		PhysicalIfName:   d.PhysicalIfName,
		HardwareAddress:  d.HardwareAddress,
		MTU:              d.MTU,
		TotalRXQueues:    d.TotalRXQueues,
		ReservedQueueIDs: d.ReservedQueueIDs,
		Prepared:         d.Prepared,
		ShareID:          d.ShareID,
		PodIfName:        d.PodIfName,
		PhysicalQueueID:  d.PhysicalQueueID,
		VirtualQueueID:   d.VirtualQueueID,
	})
}

func (d *RXQueueDevice) UnmarshalBinary(data []byte) error {
	var state deviceState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.PhysicalIfName == "" {
		return errors.New("RX queue device is missing its physical interface name")
	}
	if len(state.ReservedQueueIDs) == 0 {
		return errors.New("RX queue device has no reserved queues")
	}
	if state.Prepared && (state.ShareID == "" || state.PodIfName == "") {
		return errors.New("prepared RX queue device is missing its allocation identity")
	}

	d.PhysicalIfName = state.PhysicalIfName
	d.HardwareAddress = state.HardwareAddress
	d.MTU = state.MTU
	d.TotalRXQueues = state.TotalRXQueues
	d.ReservedQueueIDs = slices.Clone(state.ReservedQueueIDs)
	d.Prepared = state.Prepared
	d.ShareID = state.ShareID
	d.PodIfName = state.PodIfName
	d.PhysicalQueueID = state.PhysicalQueueID
	d.VirtualQueueID = state.VirtualQueueID
	return nil
}
