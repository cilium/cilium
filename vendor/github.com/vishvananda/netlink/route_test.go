// +build linux

package netlink

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
)

func TestRouteAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 1, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	dstIP := net.IPv4(192, 168, 0, 42)
	routeToDstIP, err := RouteGet(dstIP)
	if err != nil {
		t.Fatal(err)
	}

	if len(routeToDstIP) == 0 {
		t.Fatal("Default route not present")
	}
	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("Route not removed properly")
	}

}

func TestRouteReplace(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 1, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	ip = net.IPv4(127, 1, 1, 2)
	route = Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteReplace(&route); err != nil {
		t.Fatal(err)
	}

	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	if len(routes) != 1 || !routes[0].Src.Equal(ip) {
		t.Fatal("Route not replaced properly")
	}

	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("Route not removed properly")
	}

}

func TestRouteAddIncomplete(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	route := Route{LinkIndex: link.Attrs().Index}
	if err := RouteAdd(&route); err == nil {
		t.Fatal("Adding incomplete route should fail")
	}
}

func expectRouteUpdate(ch <-chan RouteUpdate, t uint16, dst net.IP) bool {
	for {
		timeout := time.After(time.Minute)
		select {
		case update := <-ch:
			if update.Type == t && update.Route.Dst.IP.Equal(dst) {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func TestRouteSubscribe(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ch := make(chan RouteUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := RouteSubscribe(ch, done); err != nil {
		t.Fatal(err)
	}

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 1, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}

	if !expectRouteUpdate(ch, syscall.RTM_NEWROUTE, dst.IP) {
		t.Fatal("Add update not received as expected")
	}
	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	if !expectRouteUpdate(ch, syscall.RTM_DELROUTE, dst.IP) {
		t.Fatal("Del update not received as expected")
	}
}

func TestRouteSubscribeAt(t *testing.T) {
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

	// Subscribe for Route events on the custom netns
	ch := make(chan RouteUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := RouteSubscribeAt(newNs, ch, done); err != nil {
		t.Fatal(err)
	}

	// get loopback interface
	link, err := nh.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = nh.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 169, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	ip := net.IPv4(127, 100, 1, 1)
	route := Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}
	if err := nh.RouteAdd(&route); err != nil {
		t.Fatal(err)
	}

	if !expectRouteUpdate(ch, syscall.RTM_NEWROUTE, dst.IP) {
		t.Fatal("Add update not received as expected")
	}
	if err := nh.RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	if !expectRouteUpdate(ch, syscall.RTM_DELROUTE, dst.IP) {
		t.Fatal("Del update not received as expected")
	}
}

func TestRouteExtraFields(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(1, 1, 1, 1),
		Mask: net.CIDRMask(32, 32),
	}

	src := net.IPv4(127, 3, 3, 3)
	route := Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Src:       src,
		Scope:     syscall.RT_SCOPE_LINK,
		Priority:  13,
		Table:     syscall.RT_TABLE_MAIN,
		Type:      syscall.RTN_UNICAST,
		Tos:       14,
	}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteListFiltered(FAMILY_V4, &Route{
		Dst:   dst,
		Src:   src,
		Scope: syscall.RT_SCOPE_LINK,
		Table: syscall.RT_TABLE_MAIN,
		Type:  syscall.RTN_UNICAST,
		Tos:   14,
	}, RT_FILTER_DST|RT_FILTER_SRC|RT_FILTER_SCOPE|RT_FILTER_TABLE|RT_FILTER_TYPE|RT_FILTER_TOS)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	if routes[0].Scope != syscall.RT_SCOPE_LINK {
		t.Fatal("Invalid Scope. Route not added properly")
	}
	if routes[0].Priority != 13 {
		t.Fatal("Invalid Priority. Route not added properly")
	}
	if routes[0].Table != syscall.RT_TABLE_MAIN {
		t.Fatal("Invalid Scope. Route not added properly")
	}
	if routes[0].Type != syscall.RTN_UNICAST {
		t.Fatal("Invalid Type. Route not added properly")
	}
	if routes[0].Tos != 14 {
		t.Fatal("Invalid Tos. Route not added properly")
	}
}

func TestRouteMultiPath(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	idx := link.Attrs().Index
	route := Route{Dst: dst, MultiPath: []*NexthopInfo{&NexthopInfo{LinkIndex: idx}, &NexthopInfo{LinkIndex: idx}}}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(nil, FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("MultiPath Route not added properly")
	}
	if len(routes[0].MultiPath) != 2 {
		t.Fatal("MultiPath Route not added properly")
	}
}

func TestFilterDefaultRoute(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	address := &Addr{
		IPNet: &net.IPNet{
			IP:   net.IPv4(127, 0, 0, 2),
			Mask: net.CIDRMask(24, 32),
		},
	}
	if err = AddrAdd(link, address); err != nil {
		t.Fatal(err)
	}

	// Add default route
	gw := net.IPv4(127, 0, 0, 2)

	defaultRoute := Route{
		Dst: nil,
		Gw:  gw,
	}

	if err := RouteAdd(&defaultRoute); err != nil {
		t.Fatal(err)
	}

	// add an extra route
	dst := &net.IPNet{
		IP:   net.IPv4(192, 168, 0, 0),
		Mask: net.CIDRMask(24, 32),
	}

	extraRoute := Route{
		Dst: dst,
		Gw:  gw,
	}

	if err := RouteAdd(&extraRoute); err != nil {
		t.Fatal(err)
	}
	var filterTests = []struct {
		filter   *Route
		mask     uint64
		expected net.IP
	}{
		{
			&Route{Dst: nil},
			RT_FILTER_DST,
			gw,
		},
		{
			&Route{Dst: dst},
			RT_FILTER_DST,
			gw,
		},
	}

	for _, f := range filterTests {
		routes, err := RouteListFiltered(FAMILY_V4, f.filter, f.mask)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 {
			t.Fatal("Route not filtered properly")
		}
		if !routes[0].Gw.Equal(gw) {
			t.Fatal("Unexpected Gateway")
		}
	}

}

func TestMPLSRouteAddDel(t *testing.T) {
	tearDown := setUpMPLSNetlinkTest(t)
	defer tearDown()

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	mplsDst := 100
	route := Route{
		LinkIndex: link.Attrs().Index,
		MPLSDst:   &mplsDst,
		NewDst: &MPLSDestination{
			Labels: []int{200, 300},
		},
	}
	if err := RouteAdd(&route); err != nil {
		t.Fatal(err)
	}
	routes, err := RouteList(link, FAMILY_MPLS)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatal("Route not added properly")
	}

	if err := RouteDel(&route); err != nil {
		t.Fatal(err)
	}
	routes, err = RouteList(link, FAMILY_MPLS)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatal("Route not removed properly")
	}

}
