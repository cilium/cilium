// +build linux

package netlink

import (
	"bytes"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
)

const (
	testTxQLen    int = 100
	defaultTxQLen int = 1000
)

func testLinkAddDel(t *testing.T, link Link) {
	links, err := LinkList()
	if err != nil {
		t.Fatal(err)
	}

	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	base := link.Attrs()

	result, err := LinkByName(base.Name)
	if err != nil {
		t.Fatal(err)
	}

	rBase := result.Attrs()

	if vlan, ok := link.(*Vlan); ok {
		other, ok := result.(*Vlan)
		if !ok {
			t.Fatal("Result of create is not a vlan")
		}
		if vlan.VlanId != other.VlanId {
			t.Fatal("Link.VlanId id doesn't match")
		}
	}

	if veth, ok := result.(*Veth); ok {
		if rBase.TxQLen != base.TxQLen {
			t.Fatalf("qlen is %d, should be %d", rBase.TxQLen, base.TxQLen)
		}
		if rBase.MTU != base.MTU {
			t.Fatalf("MTU is %d, should be %d", rBase.MTU, base.MTU)
		}

		if original, ok := link.(*Veth); ok {
			if original.PeerName != "" {
				var peer *Veth
				other, err := LinkByName(original.PeerName)
				if err != nil {
					t.Fatalf("Peer %s not created", veth.PeerName)
				}
				if peer, ok = other.(*Veth); !ok {
					t.Fatalf("Peer %s is incorrect type", veth.PeerName)
				}
				if peer.TxQLen != testTxQLen {
					t.Fatalf("TxQLen of peer is %d, should be %d", peer.TxQLen, testTxQLen)
				}
			}
		}
	} else {
		// recent kernels set the parent index for veths in the response
		if rBase.ParentIndex == 0 && base.ParentIndex != 0 {
			t.Fatalf("Created link doesn't have parent %d but it should", base.ParentIndex)
		} else if rBase.ParentIndex != 0 && base.ParentIndex == 0 {
			t.Fatalf("Created link has parent %d but it shouldn't", rBase.ParentIndex)
		} else if rBase.ParentIndex != 0 && base.ParentIndex != 0 {
			if rBase.ParentIndex != base.ParentIndex {
				t.Fatalf("Link.ParentIndex doesn't match %d != %d", rBase.ParentIndex, base.ParentIndex)
			}
		}
	}

	if vxlan, ok := link.(*Vxlan); ok {
		other, ok := result.(*Vxlan)
		if !ok {
			t.Fatal("Result of create is not a vxlan")
		}
		compareVxlan(t, vxlan, other)
	}

	if ipv, ok := link.(*IPVlan); ok {
		other, ok := result.(*IPVlan)
		if !ok {
			t.Fatal("Result of create is not a ipvlan")
		}
		if ipv.Mode != other.Mode {
			t.Fatalf("Got unexpected mode: %d, expected: %d", other.Mode, ipv.Mode)
		}
	}

	if macv, ok := link.(*Macvlan); ok {
		other, ok := result.(*Macvlan)
		if !ok {
			t.Fatal("Result of create is not a macvlan")
		}
		if macv.Mode != other.Mode {
			t.Fatalf("Got unexpected mode: %d, expected: %d", other.Mode, macv.Mode)
		}
	}

	if macv, ok := link.(*Macvtap); ok {
		other, ok := result.(*Macvtap)
		if !ok {
			t.Fatal("Result of create is not a macvtap")
		}
		if macv.Mode != other.Mode {
			t.Fatalf("Got unexpected mode: %d, expected: %d", other.Mode, macv.Mode)
		}
	}

	if _, ok := link.(*Vti); ok {
		_, ok := result.(*Vti)
		if !ok {
			t.Fatal("Result of create is not a vti")
		}
	}

	if _, ok := link.(*Iptun); ok {
		_, ok := result.(*Iptun)
		if !ok {
			t.Fatal("Result of create is not a iptun")
		}
	}

	if err = LinkDel(link); err != nil {
		t.Fatal(err)
	}

	links, err = LinkList()
	if err != nil {
		t.Fatal(err)
	}

	for _, l := range links {
		if l.Attrs().Name == link.Attrs().Name {
			t.Fatal("Link not removed properly")
		}
	}
}

func compareVxlan(t *testing.T, expected, actual *Vxlan) {

	if actual.VxlanId != expected.VxlanId {
		t.Fatal("Vxlan.VxlanId doesn't match")
	}
	if expected.SrcAddr != nil && !actual.SrcAddr.Equal(expected.SrcAddr) {
		t.Fatal("Vxlan.SrcAddr doesn't match")
	}
	if expected.Group != nil && !actual.Group.Equal(expected.Group) {
		t.Fatal("Vxlan.Group doesn't match")
	}
	if expected.TTL != -1 && actual.TTL != expected.TTL {
		t.Fatal("Vxlan.TTL doesn't match")
	}
	if expected.TOS != -1 && actual.TOS != expected.TOS {
		t.Fatal("Vxlan.TOS doesn't match")
	}
	if actual.Learning != expected.Learning {
		t.Fatal("Vxlan.Learning doesn't match")
	}
	if actual.Proxy != expected.Proxy {
		t.Fatal("Vxlan.Proxy doesn't match")
	}
	if actual.RSC != expected.RSC {
		t.Fatal("Vxlan.RSC doesn't match")
	}
	if actual.L2miss != expected.L2miss {
		t.Fatal("Vxlan.L2miss doesn't match")
	}
	if actual.L3miss != expected.L3miss {
		t.Fatal("Vxlan.L3miss doesn't match")
	}
	if actual.GBP != expected.GBP {
		t.Fatal("Vxlan.GBP doesn't match")
	}
	if expected.NoAge {
		if !actual.NoAge {
			t.Fatal("Vxlan.NoAge doesn't match")
		}
	} else if expected.Age > 0 && actual.Age != expected.Age {
		t.Fatal("Vxlan.Age doesn't match")
	}
	if expected.Limit > 0 && actual.Limit != expected.Limit {
		t.Fatal("Vxlan.Limit doesn't match")
	}
	if expected.Port > 0 && actual.Port != expected.Port {
		t.Fatal("Vxlan.Port doesn't match")
	}
	if expected.PortLow > 0 || expected.PortHigh > 0 {
		if actual.PortLow != expected.PortLow {
			t.Fatal("Vxlan.PortLow doesn't match")
		}
		if actual.PortHigh != expected.PortHigh {
			t.Fatal("Vxlan.PortHigh doesn't match")
		}
	}
}

func TestLinkAddDelDummy(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Dummy{LinkAttrs{Name: "foo"}})
}

func TestLinkAddDelIfb(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Ifb{LinkAttrs{Name: "foo"}})
}

func TestLinkAddDelBridge(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Bridge{LinkAttrs{Name: "foo", MTU: 1400}})
}

func TestLinkAddDelGretap(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Gretap{
		LinkAttrs: LinkAttrs{Name: "foo"},
		IKey:      0x101,
		OKey:      0x101,
		PMtuDisc:  1,
		Local:     net.IPv4(127, 0, 0, 1),
		Remote:    net.IPv4(127, 0, 0, 1)})
}

func TestLinkAddDelVlan(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	testLinkAddDel(t, &Vlan{LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index}, 900})

	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelMacvlan(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	testLinkAddDel(t, &Macvlan{
		LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
		Mode:      MACVLAN_MODE_PRIVATE,
	})

	testLinkAddDel(t, &Macvlan{
		LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
		Mode:      MACVLAN_MODE_BRIDGE,
	})

	testLinkAddDel(t, &Macvlan{
		LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
		Mode:      MACVLAN_MODE_VEPA,
	})

	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelMacvtap(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	testLinkAddDel(t, &Macvtap{
		Macvlan: Macvlan{
			LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
			Mode:      MACVLAN_MODE_PRIVATE,
		},
	})

	testLinkAddDel(t, &Macvtap{
		Macvlan: Macvlan{
			LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
			Mode:      MACVLAN_MODE_BRIDGE,
		},
	})

	testLinkAddDel(t, &Macvtap{
		Macvlan: Macvlan{
			LinkAttrs: LinkAttrs{Name: "bar", ParentIndex: parent.Attrs().Index},
			Mode:      MACVLAN_MODE_VEPA,
		},
	})

	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelVeth(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	veth := &Veth{LinkAttrs: LinkAttrs{Name: "foo", TxQLen: testTxQLen, MTU: 1400}, PeerName: "bar"}
	testLinkAddDel(t, veth)
}

func TestLinkAddDelBond(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, NewLinkBond(LinkAttrs{Name: "foo"}))
}

func TestLinkAddVethWithDefaultTxQLen(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	la := NewLinkAttrs()
	la.Name = "foo"

	veth := &Veth{LinkAttrs: la, PeerName: "bar"}
	if err := LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if veth, ok := link.(*Veth); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if veth.TxQLen != defaultTxQLen {
			t.Fatalf("TxQLen is %d, should be %d", veth.TxQLen, defaultTxQLen)
		}
	}
	peer, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if veth, ok := peer.(*Veth); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if veth.TxQLen != defaultTxQLen {
			t.Fatalf("TxQLen is %d, should be %d", veth.TxQLen, defaultTxQLen)
		}
	}
}

func TestLinkAddVethWithZeroTxQLen(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	la := NewLinkAttrs()
	la.Name = "foo"
	la.TxQLen = 0

	veth := &Veth{LinkAttrs: la, PeerName: "bar"}
	if err := LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if veth, ok := link.(*Veth); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if veth.TxQLen != 0 {
			t.Fatalf("TxQLen is %d, should be %d", veth.TxQLen, 0)
		}
	}
	peer, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if veth, ok := peer.(*Veth); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if veth.TxQLen != 0 {
			t.Fatalf("TxQLen is %d, should be %d", veth.TxQLen, 0)
		}
	}
}

func TestLinkAddDummyWithTxQLen(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	la := NewLinkAttrs()
	la.Name = "foo"
	la.TxQLen = 1500

	dummy := &Dummy{LinkAttrs: la}
	if err := LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if dummy, ok := link.(*Dummy); !ok {
		t.Fatalf("unexpected link type: %T", link)
	} else {
		if dummy.TxQLen != 1500 {
			t.Fatalf("TxQLen is %d, should be %d", dummy.TxQLen, 1500)
		}
	}
}

func TestLinkAddDelBridgeMaster(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	master := &Bridge{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}
	testLinkAddDel(t, &Dummy{LinkAttrs{Name: "bar", MasterIndex: master.Attrs().Index}})

	if err := LinkDel(master); err != nil {
		t.Fatal(err)
	}
}

func TestLinkSetUnsetResetMaster(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	master := &Bridge{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}

	newmaster := &Bridge{LinkAttrs{Name: "bar"}}
	if err := LinkAdd(newmaster); err != nil {
		t.Fatal(err)
	}

	slave := &Dummy{LinkAttrs{Name: "baz"}}
	if err := LinkAdd(slave); err != nil {
		t.Fatal(err)
	}

	nonexistsmaster := &Bridge{LinkAttrs{Name: "foobar"}}

	if err := LinkSetMaster(slave, nonexistsmaster); err == nil {
		t.Fatal("error expected")
	}

	if err := LinkSetMaster(slave, master); err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().MasterIndex != master.Attrs().Index {
		t.Fatal("Master not set properly")
	}

	if err := LinkSetMaster(slave, newmaster); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().MasterIndex != newmaster.Attrs().Index {
		t.Fatal("Master not reset properly")
	}

	if err := LinkSetNoMaster(slave); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().MasterIndex != 0 {
		t.Fatal("Master not unset properly")
	}
	if err := LinkDel(slave); err != nil {
		t.Fatal(err)
	}

	if err := LinkDel(newmaster); err != nil {
		t.Fatal(err)
	}

	if err := LinkDel(master); err != nil {
		t.Fatal(err)
	}
}

func TestLinkSetNs(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	basens, err := netns.Get()
	if err != nil {
		t.Fatal("Failed to get basens")
	}
	defer basens.Close()

	newns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns")
	}
	defer newns.Close()

	link := &Veth{LinkAttrs{Name: "foo"}, "bar"}
	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	peer, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	LinkSetNsFd(peer, int(basens))
	if err != nil {
		t.Fatal("Failed to set newns for link")
	}

	_, err = LinkByName("bar")
	if err == nil {
		t.Fatal("Link bar is still in newns")
	}

	err = netns.Set(basens)
	if err != nil {
		t.Fatal("Failed to set basens")
	}

	peer, err = LinkByName("bar")
	if err != nil {
		t.Fatal("Link is not in basens")
	}

	if err := LinkDel(peer); err != nil {
		t.Fatal(err)
	}

	err = netns.Set(newns)
	if err != nil {
		t.Fatal("Failed to set newns")
	}

	_, err = LinkByName("foo")
	if err == nil {
		t.Fatal("Other half of veth pair not deleted")
	}

}

func TestLinkAddDelVxlan(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{
		LinkAttrs{Name: "foo"},
	}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	vxlan := Vxlan{
		LinkAttrs: LinkAttrs{
			Name: "bar",
		},
		VxlanId:      10,
		VtepDevIndex: parent.Index,
		Learning:     true,
		L2miss:       true,
		L3miss:       true,
	}

	testLinkAddDel(t, &vxlan)
	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelVxlanGbp(t *testing.T) {
	if os.Getenv("TRAVIS_BUILD_DIR") != "" {
		t.Skipf("Kernel in travis is too old for this test")
	}

	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Dummy{
		LinkAttrs{Name: "foo"},
	}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	vxlan := Vxlan{
		LinkAttrs: LinkAttrs{
			Name: "bar",
		},
		VxlanId:      10,
		VtepDevIndex: parent.Index,
		Learning:     true,
		L2miss:       true,
		L3miss:       true,
		GBP:          true,
	}

	testLinkAddDel(t, &vxlan)
	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelIPVlanL2(t *testing.T) {
	if os.Getenv("TRAVIS_BUILD_DIR") != "" {
		t.Skipf("Kernel in travis is too old for this test")
	}
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	ipv := IPVlan{
		LinkAttrs: LinkAttrs{
			Name:        "bar",
			ParentIndex: parent.Index,
		},
		Mode: IPVLAN_MODE_L2,
	}

	testLinkAddDel(t, &ipv)
}

func TestLinkAddDelIPVlanL3(t *testing.T) {
	if os.Getenv("TRAVIS_BUILD_DIR") != "" {
		t.Skipf("Kernel in travis is too old for this test")
	}
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	parent := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}

	ipv := IPVlan{
		LinkAttrs: LinkAttrs{
			Name:        "bar",
			ParentIndex: parent.Index,
		},
		Mode: IPVLAN_MODE_L3,
	}

	testLinkAddDel(t, &ipv)
}

func TestLinkAddDelIPVlanNoParent(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ipv := IPVlan{
		LinkAttrs: LinkAttrs{
			Name: "bar",
		},
		Mode: IPVLAN_MODE_L3,
	}
	err := LinkAdd(&ipv)
	if err == nil {
		t.Fatal("Add should fail if ipvlan creating without ParentIndex")
	}
	if err.Error() != "Can't create ipvlan link without ParentIndex" {
		t.Fatalf("Error should be about missing ParentIndex, got %q", err)
	}
}

func TestLinkByIndex(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	dummy := &Dummy{LinkAttrs{Name: "dummy"}}
	if err := LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}

	found, err := LinkByIndex(dummy.Index)
	if err != nil {
		t.Fatal(err)
	}

	if found.Attrs().Index != dummy.Attrs().Index {
		t.Fatalf("Indices don't match: %v != %v", found.Attrs().Index, dummy.Attrs().Index)
	}

	LinkDel(dummy)

	// test not found
	_, err = LinkByIndex(dummy.Attrs().Index)
	if err == nil {
		t.Fatalf("LinkByIndex(%v) found deleted link", err)
	}
}

func TestLinkSet(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	iface := &Dummy{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(iface); err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}

	err = LinkSetName(link, "bar")
	if err != nil {
		t.Fatalf("Could not change interface name: %v", err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatalf("Interface name not changed: %v", err)
	}

	err = LinkSetMTU(link, 1400)
	if err != nil {
		t.Fatalf("Could not set MTU: %v", err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().MTU != 1400 {
		t.Fatal("MTU not changed!")
	}

	addr, err := net.ParseMAC("00:12:34:56:78:AB")
	if err != nil {
		t.Fatal(err)
	}

	err = LinkSetHardwareAddr(link, addr)
	if err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(link.Attrs().HardwareAddr, addr) {
		t.Fatalf("hardware address not changed!")
	}

	err = LinkSetAlias(link, "barAlias")
	if err != nil {
		t.Fatalf("Could not set alias: %v", err)
	}

	link, err = LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	if link.Attrs().Alias != "barAlias" {
		t.Fatalf("alias not changed!")
	}

	link, err = LinkByAlias("barAlias")
	if err != nil {
		t.Fatal(err)
	}
}

func expectLinkUpdate(ch <-chan LinkUpdate, ifaceName string, up bool) bool {
	for {
		timeout := time.After(time.Minute)
		select {
		case update := <-ch:
			if ifaceName == update.Link.Attrs().Name && (update.IfInfomsg.Flags&syscall.IFF_UP != 0) == up {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func TestLinkSubscribe(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ch := make(chan LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := LinkSubscribe(ch, done); err != nil {
		t.Fatal(err)
	}

	link := &Veth{LinkAttrs{Name: "foo", TxQLen: testTxQLen, MTU: 1400}, "bar"}
	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "foo", false) {
		t.Fatal("Add update not received as expected")
	}

	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "foo", true) {
		t.Fatal("Link Up update not received as expected")
	}

	if err := LinkDel(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "foo", false) {
		t.Fatal("Del update not received as expected")
	}
}

func TestLinkSubscribeAt(t *testing.T) {
	skipUnlessRoot(t)

	// Create an handle on a custom netns
	newNs, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer newNs.Close()

	nh, err := NewHandleAt(newNs)
	if err != nil {
		t.Fatal(err)
	}
	defer nh.Delete()

	// Subscribe for Link events on the custom netns
	ch := make(chan LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := LinkSubscribeAt(newNs, ch, done); err != nil {
		t.Fatal(err)
	}

	link := &Veth{LinkAttrs{Name: "test", TxQLen: testTxQLen, MTU: 1400}, "bar"}
	if err := nh.LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "test", false) {
		t.Fatal("Add update not received as expected")
	}

	if err := nh.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "test", true) {
		t.Fatal("Link Up update not received as expected")
	}

	if err := nh.LinkDel(link); err != nil {
		t.Fatal(err)
	}

	if !expectLinkUpdate(ch, "test", false) {
		t.Fatal("Del update not received as expected")
	}
}

func TestLinkStats(t *testing.T) {
	defer setUpNetlinkTest(t)()

	// Create a veth pair and verify the cross-stats once both
	// ends are brought up and some ICMPv6 packets are exchanged
	v0 := "v0"
	v1 := "v1"

	vethLink := &Veth{LinkAttrs: LinkAttrs{Name: v0}, PeerName: v1}
	if err := LinkAdd(vethLink); err != nil {
		t.Fatal(err)
	}

	veth0, err := LinkByName(v0)
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(veth0); err != nil {
		t.Fatal(err)
	}

	veth1, err := LinkByName(v1)
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(veth1); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	// verify statistics
	veth0, err = LinkByName(v0)
	if err != nil {
		t.Fatal(err)
	}
	veth1, err = LinkByName(v1)
	if err != nil {
		t.Fatal(err)
	}
	v0Stats := veth0.Attrs().Statistics
	v1Stats := veth1.Attrs().Statistics
	if v0Stats.RxPackets != v1Stats.TxPackets || v0Stats.TxPackets != v1Stats.RxPackets ||
		v0Stats.RxBytes != v1Stats.TxBytes || v0Stats.TxBytes != v1Stats.RxBytes {
		t.Fatalf("veth ends counters differ:\n%v\n%v", v0Stats, v1Stats)
	}
}

func TestLinkXdp(t *testing.T) {
	links, err := LinkList()
	if err != nil {
		t.Fatal(err)
	}
	var testXdpLink Link
	for _, link := range links {
		if link.Attrs().Xdp != nil && !link.Attrs().Xdp.Attached {
			testXdpLink = link
			break
		}
	}
	if testXdpLink == nil {
		t.Skipf("No link supporting XDP found")
	}
	fd, err := loadSimpleBpf(BPF_PROG_TYPE_XDP, 2 /*XDP_PASS*/)
	if err != nil {
		t.Skipf("Loading bpf program failed: %s", err)
	}
	if err := LinkSetXdpFd(testXdpLink, fd); err != nil {
		t.Fatal(err)
	}
	if err := LinkSetXdpFd(testXdpLink, -1); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelIptun(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Iptun{
		LinkAttrs: LinkAttrs{Name: "iptunfoo"},
		PMtuDisc:  1,
		Local:     net.IPv4(127, 0, 0, 1),
		Remote:    net.IPv4(127, 0, 0, 1)})
}

func TestLinkAddDelVti(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Vti{
		LinkAttrs: LinkAttrs{Name: "vtifoo"},
		IKey:      0x101,
		OKey:      0x101,
		Local:     net.IPv4(127, 0, 0, 1),
		Remote:    net.IPv4(127, 0, 0, 1)})
}

func TestLinkSubscribeWithProtinfo(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	master := &Bridge{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}

	slave := &Veth{
		LinkAttrs: LinkAttrs{
			Name:        "bar",
			TxQLen:      testTxQLen,
			MTU:         1400,
			MasterIndex: master.Attrs().Index,
		},
		PeerName: "bar-peer",
	}
	if err := LinkAdd(slave); err != nil {
		t.Fatal(err)
	}

	ch := make(chan LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := LinkSubscribe(ch, done); err != nil {
		t.Fatal(err)
	}

	if err := LinkSetHairpin(slave, true); err != nil {
		t.Fatal(err)
	}

	select {
	case update := <-ch:
		if !(update.Attrs().Name == "bar" && update.Attrs().Protinfo != nil &&
			update.Attrs().Protinfo.Hairpin) {
			t.Fatal("Hairpin update not received as expected")
		}
	case <-time.After(time.Minute):
		t.Fatal("Hairpin update timed out")
	}

	if err := LinkDel(slave); err != nil {
		t.Fatal(err)
	}

	if err := LinkDel(master); err != nil {
		t.Fatal(err)
	}
}
