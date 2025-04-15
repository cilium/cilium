// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive"
)

// fakeSender mocks the GARP Sender, allowing for a feedback channel.
type fakeSender struct {
	sent chan fakeGarp
}

type fakeGarp struct {
	addr  netip.Addr
	iface Interface
}

func (fs *fakeSender) Send(iface Interface, ip netip.Addr) error {
	fs.sent <- fakeGarp{addr: ip, iface: iface}
	return nil
}

// InterfaceByIndex get Interface by ifindex
func (fs *fakeSender) InterfaceByIndex(idx int) (Interface, error) {
	def := fakeDevices[idx]
	if def == nil {
		return Interface{}, fmt.Errorf("Device does not exit: %d", idx)
	}

	return Interface{
		iface: &net.Interface{
			Index: def.Index,
			Name:  def.Name,
		},
	}, nil
}

var fakeDevices = map[int]*tables.Device{
	1: {
		Index:    1,
		Name:     "lo",
		Selected: false,
	},
	2: {
		Index:    2,
		Name:     "eth0",
		Selected: true,
	},
	3: {
		Index:    3,
		Name:     "eth0.0",
		Selected: false,
	},
	4: {
		Index:    4,
		Name:     "eth0.1",
		Selected: true,
	},
	5: {
		Index:    5,
		Name:     "ens1",
		Selected: true,
	},
}

func fixture(t *testing.T, c *Config) (
	chan fakeGarp,
	*statedb.DB,
	statedb.RWTable[*tables.Device],
	*processor,
) {
	// These allow us to inspect the state of the processor cell.
	var (
		garpSent = make(chan fakeGarp, 10)
		db       *statedb.DB
		devices  statedb.RWTable[*tables.Device]
		proc     *processor
	)

	h := hive.New(cell.Module(
		"test-garp-processor-cell",
		"TestProcessorCell",

		cell.Config(defaultConfig),

		cell.Provide(
			// Provide devices table, but not the devices controller.
			// We have full control over contents during the test.
			tables.NewDeviceTable,
			// Provide the read-only table, which is what the processor uses.
			statedb.RWTable[*tables.Device].ToTable,

			// Replace the actual GARP sender with a fake one, so we can see when
			// a GARP packet would have been sent.
			func() Sender { return &fakeSender{sent: garpSent} },

			// Stub out the endpoint manager, so we can call the processor callbacks
			// instead.
			func() endpointmanager.EndpointManager { return nil },

			// Component under test.
			newGARPProcessor,
		),

		cell.Invoke(
			// Register the devices table, required for it to work.
			statedb.RegisterTable[*tables.Device],

			func(dbParam *statedb.DB, devicesParam statedb.RWTable[*tables.Device], procParam *processor) {
				db = dbParam
				devices = devicesParam
				proc = procParam
			},
		),
	))

	// Apply the config so that the GARP cell will initialise.s
	hive.AddConfigOverride(h, func(cfg *Config) {
		cfg.EnableL2PodAnnouncements = c.EnableL2PodAnnouncements
		cfg.L2PodAnnouncementsInterface = c.L2PodAnnouncementsInterface
		cfg.L2PodAnnouncementsInterfacePattern = c.L2PodAnnouncementsInterfacePattern
	})

	// Populate hive cells but do not start the hive (we don't need a running hive for the tests).
	if err := h.Populate(hivetest.Logger(t)); err != nil {
		t.Fatal(err)
	}

	// Initialize our fake devices
	tx := db.WriteTxn(devices)
	for _, d := range fakeDevices {
		_, _, err := devices.Insert(tx, d)
		if err != nil {
			t.Fatal(err)
		}
	}
	tx.Commit()

	// Update the interfaces of the processor.
	proc.updateInterfaces()

	return garpSent, db, devices, proc
}

func collect(c chan fakeGarp) []fakeGarp {
	var garps []fakeGarp
	for {
		select {
		case garp := <-c:
			garps = append(garps, garp)
		default:
			return garps
		}
	}
}

func TestProcessorSingleInterface(t *testing.T) {
	cfg := &Config{
		EnableL2PodAnnouncements:           true,
		L2PodAnnouncementsInterface:        "eth0",
		L2PodAnnouncementsInterfacePattern: "",
	}
	garpSent, _, _, proc := fixture(t, cfg)

	ep1 := &endpoint.Endpoint{ID: 1, IPv4: netip.MustParseAddr("1.2.3.4")}
	ep2 := &endpoint.Endpoint{ID: 2, IPv4: netip.MustParseAddr("4.3.2.1")}

	// On first event we expect a GARP to be sent.
	proc.EndpointCreated(ep1)
	garps := collect(garpSent)
	require.Len(t, garps, 1)
	require.Equal(t, garps[0].addr.String(), ep1.IPv4.String())
	require.Equal(t, garps[0].iface.iface.Name, cfg.L2PodAnnouncementsInterface)

	// On second event we expect no GARP to be sent.
	proc.EndpointCreated(ep1)
	require.Empty(t, collect(garpSent))

	// First event for second endpoint should trigger a GARP.
	proc.EndpointCreated(ep2)
	garps = collect(garpSent)
	require.Len(t, garps, 1)
	require.Equal(t, garps[0].addr.String(), ep2.IPv4.String())
	require.Equal(t, garps[0].iface.iface.Name, cfg.L2PodAnnouncementsInterface)

	// Second event for second endpoint should not trigger a GARP.
	proc.EndpointCreated(ep2)
	require.Empty(t, collect(garpSent))

	// No GARP should be sent on deletion.
	proc.EndpointDeleted(ep1, endpoint.DeleteConfig{})
	require.Empty(t, collect(garpSent))

	// When recreated after delete, a GARP should be sent.
	proc.EndpointCreated(ep1)
	garps = collect(garpSent)
	require.Len(t, garps, 1)
	require.Equal(t, garps[0].addr.String(), ep1.IPv4.String())
	require.Equal(t, garps[0].iface.iface.Name, cfg.L2PodAnnouncementsInterface)

	// But GARP should still not be set for recreated ep2.
	proc.EndpointCreated(ep2)
	require.Empty(t, collect(garpSent))
}

func TestProcessorHappyPathMultipleInterface(t *testing.T) {
	cfg := &Config{
		EnableL2PodAnnouncements:           true,
		L2PodAnnouncementsInterface:        "",
		L2PodAnnouncementsInterfacePattern: "^(eth0|ens1)$",
	}
	garpSent, _, _, proc := fixture(t, cfg)

	ep1 := &endpoint.Endpoint{ID: 1, IPv4: netip.MustParseAddr("1.2.3.4")}
	// On first event we expect a GARP to be sent.
	proc.EndpointCreated(ep1)
	garps := collect(garpSent)
	require.Len(t, garps, 2)
	require.Equal(t, garps[0].addr.String(), ep1.IPv4.String())
	gotEth0 := garps[0].iface.iface.Name == "eth0" || garps[1].iface.iface.Name == "eth0"
	gotEns1 := garps[0].iface.iface.Name == "ens1" || garps[1].iface.iface.Name == "ens1"
	if !(gotEth0 && gotEns1) {
		t.Fatalf("Expected GARP to be sent on both eth0 and ens1, got: %v", garps)
	}
}

func TestProcessorOnlySelected(t *testing.T) {
	cfg := &Config{
		EnableL2PodAnnouncements:           true,
		L2PodAnnouncementsInterface:        "",
		L2PodAnnouncementsInterfacePattern: ".*",
	}
	garpSent, _, _, proc := fixture(t, cfg)

	ep1 := &endpoint.Endpoint{ID: 1, IPv4: netip.MustParseAddr("1.2.3.4")}
	proc.EndpointCreated(ep1)
	garps := collect(garpSent)
	for _, d := range fakeDevices {
		contains := slices.ContainsFunc(garps, func(g fakeGarp) bool {
			return g.iface.iface.Name == d.Name
		})
		if d.Selected && !contains {
			t.Fatalf("Expected GARP to be sent on selected interface %s", d.Name)
		}
		if !d.Selected && contains {
			t.Fatalf("Expected GARP to not be sent on non-selected interface %s", d.Name)
		}
	}
}

func TestProcessorDynamicUpdates(t *testing.T) {
	cfg := &Config{
		EnableL2PodAnnouncements:           true,
		L2PodAnnouncementsInterface:        "",
		L2PodAnnouncementsInterfacePattern: ".*",
	}
	garpSent, db, devices, proc := fixture(t, cfg)

	ep1 := &endpoint.Endpoint{ID: 1, IPv4: netip.MustParseAddr("1.2.3.4")}
	proc.EndpointCreated(ep1)
	require.Len(t, collect(garpSent), 3)
	proc.EndpointDeleted(ep1, endpoint.DeleteConfig{})

	tx := db.WriteTxn(devices)
	obj, _, found := devices.Get(tx, tables.DeviceIDIndex.Query(5))
	require.True(t, found)
	devices.Delete(tx, obj)
	tx.Commit()

	// Simulate the job processing the table change.
	proc.updateInterfaces()

	// Assert that we now have a different set of interfaces to which GARPs are sent.
	proc.EndpointCreated(ep1)
	require.Len(t, collect(garpSent), 2)
}
