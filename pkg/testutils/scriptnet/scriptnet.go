// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scriptnet

import (
	"fmt"
	"maps"
	"net"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/cilium/hive/script"
	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
)

type NetNSManager struct {
	origNS         netns.NsHandle
	currentNS      netns.NsHandle
	testNamespaces map[string]netns.NsHandle
}

const rootNS = "root"

// NewNSManager creates a new uninitialized NetNSManager.
func NewNSManager(t testing.TB) (*NetNSManager, error) {
	return &NetNSManager{
		testNamespaces: make(map[string]netns.NsHandle),
	}, nil
}

// LockThreadAndInitialize locks the current thread to the OS thread and initializes the NetNSManager.
// It also registers a cleanup function, unlocking the thread on test completion, switching to the original
// network namespace, and closing all test namespaces.
//
// The `isolated` parameter determines whether to start in the current network namespace or to completely
// isolate the test environment by starting in a new network namespace.
// Non-isolated mode allows a script to setup a link to the host network namespace but risks a mistake in a script
// corrupting the host network namespace.
func (nsm *NetNSManager) LockThreadAndInitialize(t testing.TB, isolated bool) error {
	runtime.LockOSThread()
	t.Cleanup(func() {
		nsm.close()
		runtime.UnlockOSThread()
	})

	origNS, err := netns.Get()
	if err != nil {
		return err
	}

	nsm.origNS = origNS
	nsm.currentNS = origNS

	// If isolated, we create a new root namespace and switch to it.
	if isolated {
		_, err := nsm.createNamespace(rootNS)
		if err != nil {
			return fmt.Errorf("failed to create root namespace: %w", err)
		}

		err = nsm.switchNamespace(rootNS)
		if err != nil {
			return fmt.Errorf("failed to switch to root namespace: %w", err)
		}
	} else {
		// If not isolated, we keep the original namespace as the current one
		nsm.testNamespaces[rootNS] = origNS
	}

	return nil
}

func (nsm *NetNSManager) close() error {
	// Restore the original namespace
	if nsm.origNS.IsOpen() {
		if err := netns.Set(nsm.origNS); err != nil {
			return err
		}
		return nsm.origNS.Close()
	}

	// Close all test namespaces
	for _, ns := range nsm.testNamespaces {
		if ns.IsOpen() {
			if err := ns.Close(); err != nil {
				return err
			}
		}
	}

	return nil
}

// Commands provides a set of script commands for managing network namespaces, links, addresses, and routes.
// These are designed to be used in test scripts to create ephemeral network namespaces to perform tests.
func (nsm *NetNSManager) Commands() map[string]script.Cmd {
	if len(nsm.testNamespaces) == 0 {
		panic("NetNSManager is not initialized, call LockThreadAndInitialize first")
	}

	return map[string]script.Cmd{
		"netns/list":    netNSListCmd(nsm),
		"netns/create":  netNSCreateCmd(nsm),
		"netns/switch":  netNSSwitchCmd(nsm),
		"link/list":     linkListCmd(nsm),
		"link/add":      linkAddCmd(nsm),
		"link/set":      linkSetCmd(nsm),
		"link/del":      linkDelCmd(nsm),
		"addr/add":      addAddCmd(nsm),
		"route/list":    routeListCmd(nsm),
		"route/add":     routeAddCmd(nsm),
		"route/replace": routeReplaceCmd(nsm),
		"route/del":     routeDelCmd(nsm),
		"sysctl/get":    sysctlGetCmd(nsm),
		"sysctl/set":    sysctlSetCmd(nsm),
	}
}

func (m *NetNSManager) listNamespaces() []string {
	return slices.Sorted(maps.Keys(m.testNamespaces))
}

func (m *NetNSManager) createNamespace(name string) (netns.NsHandle, error) {
	_, found := m.testNamespaces[name]
	if found {
		return netns.None(), fmt.Errorf("namespace %q already exists", name)
	}

	ns, err := netns.New()
	if err != nil {
		return netns.None(), err
	}

	m.testNamespaces[name] = ns

	// Switch back to the current network namespace
	err = netns.Set(m.currentNS)
	if err != nil {
		return netns.None(), fmt.Errorf("failed to switch back to current namespace: %w", err)
	}

	return ns, nil
}

func (m *NetNSManager) getNamespace(name string) (netns.NsHandle, error) {
	ns, ok := m.testNamespaces[name]
	if !ok {
		return netns.None(), fmt.Errorf("namespace %q does not exist", name)
	}

	return ns, nil
}

func (m *NetNSManager) exec(name string, fn func() error) error {
	ns, err := m.getNamespace(name)
	if err != nil {
		return err
	}

	// Switch to the test namespace
	if err := netns.Set(ns); err != nil {
		return err
	}
	defer func() {
		// Restore the original namespace after execution
		netns.Set(m.currentNS)
	}()

	return fn()
}

func (m *NetNSManager) switchNamespace(name string) error {
	ns, err := m.getNamespace(name)
	if err != nil {
		return err
	}

	// Switch to the specified namespace
	if err := netns.Set(ns); err != nil {
		return err
	}

	m.currentNS = ns
	return nil
}

func (m *NetNSManager) currentNamespaceName() string {
	for name, ns := range m.testNamespaces {
		if ns == m.currentNS {
			return name
		}
	}

	return "unknown"
}

func netNSListCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List ephemeral network namespaces",
			Args:    "",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {

			namespaces := nsm.listNamespaces()
			if len(namespaces) == 0 {
				return func(s *script.State) (stdout string, stderr string, err error) {
					return "No network namespaces found.\n", "", nil
				}, nil
			}

			var sb strings.Builder
			for _, name := range namespaces {
				fmt.Fprintf(&sb, "%s\n", name)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				return sb.String(), "", nil
			}, nil
		},
	)
}

func netNSCreateCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Create a new ephemeral network namespace",
			Args:    "<name>",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			name := args[0]
			_, err := nsm.createNamespace(name)
			if err != nil {
				return nil, fmt.Errorf("failed to create namespace %q: %w", name, err)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				return fmt.Sprintf("Created network namespace %q\n", name), "", nil
			}, nil
		},
	)
}

func netNSSwitchCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Switch to an ephemeral network namespace",
			Args:    "<name>",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			name := args[0]
			if err := nsm.switchNamespace(name); err != nil {
				return nil, fmt.Errorf("failed to switch to namespace %q: %w", name, err)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				return fmt.Sprintf("Switched to network namespace %q\n", name), "", nil
			}, nil
		},
	)
}

func linkListCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List network interfaces",
			Args:    "",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			var sb strings.Builder
			err = nsm.exec(nsName, func() error {
				links, err := safenetlink.LinkList()
				if err != nil {
					return err
				}

				for _, link := range links {
					attr := link.Attrs()
					fmt.Fprintf(&sb, "%4d: %s %s <%s>\n", attr.Index, attr.Name, link.Type(), attr.Flags)
					fmt.Fprintf(&sb, "      mtu: %d, state: %s\n", attr.MTU, attr.OperState)
					if attr.HardwareAddr != nil {
						fmt.Fprintf(&sb, "      hwaddr: %s\n", attr.HardwareAddr.String())
					}

					addrs, err := safenetlink.AddrList(link, netlink.FAMILY_ALL)
					if err != nil {
						return fmt.Errorf("failed to list addresses for link %s: %w", attr.Name, err)
					}

					for _, addr := range addrs {
						fmt.Fprintf(&sb, "      addr: %s\n", addr.String())
					}
				}

				return nil
			})

			return func(s *script.State) (stdout string, stderr string, err error) {
				return sb.String(), "", nil
			}, err
		},
	)
}

func linkAddCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Add a new network interface",
			Args:    "<name> <type>",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
				fs.String("peername", "", "Name of the veth peer interface (veth only)")
				fs.String("peerns", "", "Network namespace of the veth peer (veth only)")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}

			name := args[0]
			linkType := args[1]

			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			linkAttrs := netlink.LinkAttrs{Name: name}

			err = nsm.exec(nsName, func() error {
				var link netlink.Link
				switch linkType {
				case "dummy":
					link = &netlink.Dummy{LinkAttrs: linkAttrs}
				case "veth":
					veth := &netlink.Veth{
						LinkAttrs: linkAttrs,
					}

					veth.PeerName, err = s.Flags.GetString("peername")
					if err != nil {
						return fmt.Errorf("failed to get peername flag: %w", err)
					}
					if veth.Name == "" {
						return fmt.Errorf("--peername must be specified for veth links")
					}

					peerNSName, err := s.Flags.GetString("peerns")
					if err != nil {
						return fmt.Errorf("failed to get peerns flag: %w", err)
					}
					if peerNSName != "" {
						peerNS, err := nsm.getNamespace(peerNSName)
						if err != nil {
							return fmt.Errorf("failed to get peer namespace %q: %w", peerNSName, err)
						}
						veth.PeerNamespace = netlink.NsFd(peerNS)
					}

					link = veth
				default:
					return fmt.Errorf("unsupported link type: %s", linkType)
				}

				if err := netlink.LinkAdd(link); err != nil {
					return fmt.Errorf("failed to create link %q of type %s: %w", name, linkType, err)
				}

				return nil
			})

			return func(s *script.State) (stdout string, stderr string, err error) {
				return fmt.Sprintf("Created link %q of type %s\n", name, linkType), "", nil
			}, err
		},
	)
}

func linkSetCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Set properties of a network interface",
			Args:    "<name> [key[=value]] ...",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, script.ErrUsage
			}

			if len(args) < 2 {
				return nil, fmt.Errorf("no action specified")
			}

			name := args[0]

			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			properties := map[string]func(link netlink.Link, arg string) error{
				"up": func(link netlink.Link, value string) error {
					return netlink.LinkSetUp(link)
				},
				"down": func(link netlink.Link, value string) error {
					return netlink.LinkSetDown(link)
				},
				"mtu": func(link netlink.Link, value string) error {
					mtu, err := strconv.Atoi(value)
					if err != nil {
						return fmt.Errorf("invalid mtu value %q: %w", value, err)
					}
					return netlink.LinkSetMTU(link, mtu)
				},
				"hwaddr": func(link netlink.Link, value string) error {
					hwAddr, err := net.ParseMAC(value)
					if err != nil {
						return fmt.Errorf("invalid hwaddr value %q: %w", value, err)
					}
					return netlink.LinkSetHardwareAddr(link, hwAddr)
				},
			}

			var sb strings.Builder
			err = nsm.exec(nsName, func() error {
				for _, arg := range args[1:] {
					link, err := safenetlink.LinkByName(name)
					if err != nil {
						return fmt.Errorf("failed to find link %q: %w", name, err)
					}

					key, value, _ := strings.Cut(arg, "=")
					if fn, ok := properties[key]; ok {
						if err := fn(link, value); err != nil {
							return err
						}
					} else {
						fmt.Fprintf(&sb, "Available properties:\n")
						for _, propertyName := range slices.Sorted(maps.Keys(properties)) {
							fmt.Fprintf(&sb, "  %s\n", propertyName)
						}

						return fmt.Errorf("unknown property %q", key)
					}
				}

				return nil
			})

			return func(s *script.State) (stdout string, stderr string, err error) {
				return sb.String(), "", nil
			}, err
		},
	)
}

func linkDelCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Delete a network interface",
			Args:    "<name>",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			name := args[0]

			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			err = nsm.exec(nsName, func() error {
				link, err := safenetlink.LinkByName(name)
				if err != nil {
					return fmt.Errorf("failed to find link %q: %w", name, err)
				}

				if err := netlink.LinkDel(link); err != nil {
					return fmt.Errorf("failed to delete link %q: %w", name, err)
				}

				return nil
			})

			return func(s *script.State) (stdout string, stderr string, err error) {
				return fmt.Sprintf("Deleted link %q\n", name), "", nil
			}, err
		},
	)
}

func addAddCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Add an IP address to a network interface",
			Args:    "<address> <interface>",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}

			address := args[0]
			ifaceName := args[1]

			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			err = nsm.exec(nsName, func() error {
				ipNet, err := netlink.ParseIPNet(address)
				if err != nil {
					return fmt.Errorf("failed to parse address %q: %w", address, err)
				}

				link, err := safenetlink.LinkByName(ifaceName)
				if err != nil {
					return fmt.Errorf("failed to find interface %q: %w", ifaceName, err)
				}

				addr := &netlink.Addr{IPNet: ipNet}
				if err := netlink.AddrAdd(link, addr); err != nil {
					return fmt.Errorf("failed to add address %s to interface %s: %w", address, ifaceName, err)
				}

				return nil
			})

			return func(s *script.State) (stdout string, stderr string, err error) {
				return fmt.Sprintf("Added address %s to interface %s\n", address, ifaceName), "", nil
			}, err
		},
	)
}

func destinationString(via netlink.Destination) string {
	switch d := via.(type) {
	case *netlink.Via:
		var family string
		switch d.Family() {
		case netlink.FAMILY_V4:
			family = "inet"
		case netlink.FAMILY_V6:
			family = "inet6"
		default:
			family = fmt.Sprintf("unknown(%d)", d.Family())
		}
		return fmt.Sprintf("via %s %s", family, d.Addr.String())
	default:
		return "unknown"
	}
}

func routeListCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List routes",
			Args:    "",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
				fs.String("table", "main", "Filter routes by table")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			filter := &netlink.Route{
				Table: unix.RT_TABLE_MAIN, // Default table
			}
			filterMask := netlink.RT_FILTER_TABLE
			tableStr, err := s.Flags.GetString("table")
			if err != nil {
				return nil, fmt.Errorf("failed to get table flag: %w", err)
			}
			filter.Table, err = strconv.Atoi(tableStr)
			if err != nil {
				switch tableStr {
				case "main":
					filter.Table = unix.RT_TABLE_MAIN
				case "local":
					filter.Table = unix.RT_TABLE_LOCAL
				case "default":
					filter.Table = unix.RT_TABLE_DEFAULT
				case "all":
					filter.Table = unix.RT_TABLE_UNSPEC
				default:
					return nil, fmt.Errorf("invalid table %q: must be an integer or one of 'main', 'local', 'default'", tableStr)
				}
			}

			var sb strings.Builder
			err = nsm.exec(nsName, func() error {
				routes, err := safenetlink.RouteListFiltered(netlink.FAMILY_ALL, filter, filterMask)
				if err != nil {
					return fmt.Errorf("failed to list routes: %w", err)
				}

				for _, route := range routes {
					fmt.Fprintf(&sb, "%s", route.Dst.String())

					if len(route.Gw) != 0 {
						fmt.Fprintf(&sb, " via %s", route.Gw)
					} else if route.Via != nil {
						fmt.Fprintf(&sb, " %s", destinationString(route.Via))
					}

					if route.LinkIndex != 0 {
						link, err := netlink.LinkByIndex(route.LinkIndex)
						if err != nil {
							return fmt.Errorf("Failed to find link for route %s: %w\n", route.Dst, err)
						}
						fmt.Fprintf(&sb, " dev %s", link.Attrs().Name)
					}

					fmt.Fprintf(&sb, " scope %s", route.Scope)

					if route.Src != nil {
						fmt.Fprintf(&sb, " src %s", route.Src)
					}

					if route.MTU != 0 {
						fmt.Fprintf(&sb, " mtu %d", route.MTU)
					}

					switch route.Table {
					case unix.RT_TABLE_MAIN:
						fmt.Fprintf(&sb, " table main")
					case unix.RT_TABLE_LOCAL:
						fmt.Fprintf(&sb, " table local")
					case unix.RT_TABLE_DEFAULT:
						fmt.Fprintf(&sb, " table default")
					default:
						fmt.Fprintf(&sb, " table %d", route.Table)
					}

					if route.Priority != 0 {
						fmt.Fprintf(&sb, " priority %d", route.Priority)
					}

					for _, nh := range route.MultiPath {
						parts := []string{}
						if nh.Gw != nil {
							parts = append(parts, fmt.Sprintf("via %s", nh.Gw.String()))
						} else if nh.Via != nil {
							parts = append(parts, destinationString(nh.Via))
						}
						if nh.LinkIndex != 0 {
							nhLink, err := netlink.LinkByIndex(nh.LinkIndex)
							if err != nil {
								return fmt.Errorf("Failed to find link for nexthop in route %s: %w\n", route.Dst, err)
							}
							parts = append(parts, fmt.Sprintf("dev %s", nhLink.Attrs().Name))
						}
						fmt.Fprintf(&sb, "\n    nexthop %s", strings.Join(parts, " "))
					}

					fmt.Fprintf(&sb, "\n")
				}

				return nil
			})

			return func(s *script.State) (stdout string, stderr string, err error) {
				return sb.String(), "", nil
			}, err
		},
	)
}

func routeFlags(fs *pflag.FlagSet) {
	fs.String("gateway", "", "Gateway IP address for the route")
	fs.String("dev", "", "Device name for the route")
	fs.String("table", "main", "Table to add the route to")
	fs.Int("mtu", 0, "MTU for the route")
	fs.String("proto", "", "Protocol for the route")
}

func routeFromFlags(destination string, fs *pflag.FlagSet) (*netlink.Route, error) {
	route := &netlink.Route{}

	var err error
	route.Dst, err = netlink.ParseIPNet(destination)
	if err != nil {
		return nil, fmt.Errorf("failed to parse destination %q: %w", destination, err)
	}

	gatewayStr, err := fs.GetString("gateway")
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway flag: %w", err)
	}
	if gatewayStr != "" {
		gatewayIP := net.ParseIP(gatewayStr)
		if gatewayIP == nil {
			return nil, fmt.Errorf("invalid gateway IP address %q", gatewayStr)
		}
		route.Gw = gatewayIP
	}

	devName, err := fs.GetString("dev")
	if err != nil {
		return nil, fmt.Errorf("failed to get dev flag: %w", err)
	}
	if devName != "" {
		link, err := safenetlink.LinkByName(devName)
		if err != nil {
			return nil, fmt.Errorf("failed to find device %q: %w", devName, err)
		}
		route.LinkIndex = link.Attrs().Index
	}

	tableStr, err := fs.GetString("table")
	if err != nil {
		return nil, fmt.Errorf("failed to get table flag: %w", err)
	}
	switch tableStr {
	case "main":
		route.Table = unix.RT_TABLE_MAIN
	case "local":
		route.Table = unix.RT_TABLE_LOCAL
	case "default":
		route.Table = unix.RT_TABLE_DEFAULT
	default:
		route.Table, err = strconv.Atoi(tableStr)
		if err != nil {
			return nil, fmt.Errorf("invalid table %q: must be an integer or one of 'main', 'local', 'default'", tableStr)
		}
	}

	route.MTU, err = fs.GetInt("mtu")
	if err != nil {
		return nil, fmt.Errorf("failed to get mtu flag: %w", err)
	}

	protoStr, err := fs.GetString("proto")
	if err != nil {
		return nil, fmt.Errorf("failed to get proto flag: %w", err)
	}
	if protoStr != "" {
		switch protoStr {
		case "kernel":
			route.Protocol = unix.RTPROT_KERNEL
		case "static":
			route.Protocol = unix.RTPROT_STATIC
		default:
			protoNum, err := strconv.Atoi(protoStr)
			if err != nil {
				return nil, fmt.Errorf("invalid proto %q: must be an integer or one of 'kernel', 'static'", protoStr)
			}
			route.Protocol = netlink.RouteProtocol(protoNum)
		}
	}

	return route, nil
}

func routeAddCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Add a new route",
			Args:    "<destination>",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
				routeFlags(fs)
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			destination := args[0]
			route, err := routeFromFlags(destination, s.Flags)
			if err != nil {
				return nil, err
			}

			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			err = nsm.exec(nsName, func() error {
				if err := netlink.RouteAdd(route); err != nil {
					return fmt.Errorf("failed to add route %s: %w", destination, err)
				}

				return nil
			})
			if err != nil {
				return nil, err
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				return fmt.Sprintf("Added route %s\n", destination), "", nil
			}, nil
		},
	)
}

func routeReplaceCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Replace an existing route",
			Args:    "<destination>",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
				routeFlags(fs)
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			destination := args[0]
			route, err := routeFromFlags(destination, s.Flags)
			if err != nil {
				return nil, err
			}

			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			err = nsm.exec(nsName, func() error {
				if err := netlink.RouteReplace(route); err != nil {
					return fmt.Errorf("failed to replace route %s: %w", destination, err)
				}

				return nil
			})
			if err != nil {
				return nil, err
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				return fmt.Sprintf("Replaced route %s\n", destination), "", nil
			}, nil
		},
	)
}

func routeDelCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Delete a route",
			Args:    "<destination>",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
				fs.String("gateway", "", "Gateway IP address for the route")
				fs.String("dev", "", "Device name for the route")
				fs.String("table", "main", "Table to delete the route from")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, script.ErrUsage
			}

			filter := &netlink.Route{}
			filterMask := netlink.RT_FILTER_DST

			var err error
			filter.Dst, err = netlink.ParseIPNet(args[0])
			if err != nil {
				return nil, fmt.Errorf("failed to parse destination %q: %w", args[0], err)
			}

			gatewayStr, err := s.Flags.GetString("gateway")
			if err != nil {
				return nil, fmt.Errorf("failed to get gateway flag: %w", err)
			}
			if gatewayStr != "" {
				gatewayIP := net.ParseIP(gatewayStr)
				if gatewayIP == nil {
					return nil, fmt.Errorf("invalid gateway IP address %q", gatewayStr)
				}
				filter.Gw = gatewayIP
				filterMask |= netlink.RT_FILTER_GW
			}

			devName, err := s.Flags.GetString("dev")
			if err != nil {
				return nil, fmt.Errorf("failed to get dev flag: %w", err)
			}
			if devName != "" {
				link, err := safenetlink.LinkByName(devName)
				if err != nil {
					return nil, fmt.Errorf("failed to find device %q: %w", devName, err)
				}
				filter.LinkIndex = link.Attrs().Index
				filterMask |= netlink.RT_FILTER_OIF
			}

			tableStr, err := s.Flags.GetString("table")
			if err != nil {
				return nil, fmt.Errorf("failed to get table flag: %w", err)
			}
			if tableStr != "" {
				filter.Table, err = strconv.Atoi(tableStr)
				if err != nil {
					switch tableStr {
					case "main":
						filter.Table = unix.RT_TABLE_MAIN
					case "local":
						filter.Table = unix.RT_TABLE_LOCAL
					case "default":
						filter.Table = unix.RT_TABLE_DEFAULT
					default:
						return nil, fmt.Errorf("invalid table %q: must be an integer or one of 'main', 'local', 'default'", tableStr)
					}
				}
				filterMask |= netlink.RT_FILTER_TABLE
			}

			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			err = nsm.exec(nsName, func() error {
				routes, err := safenetlink.RouteListFiltered(netlink.FAMILY_ALL, filter, filterMask)
				if err != nil {
					return fmt.Errorf("failed to list routes: %w", err)
				}

				if len(routes) == 0 {
					return fmt.Errorf("no matching routes found for %s", args[0])
				}

				if len(routes) > 1 {
					return fmt.Errorf("multiple matching routes found for %s, please specify more filters", args[0])
				}

				route := routes[0]
				if err := netlink.RouteDel(&route); err != nil {
					return fmt.Errorf("failed to delete route %s: %w", args[0], err)
				}

				return nil
			})
			if err != nil {
				return nil, err
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				return fmt.Sprintf("Deleted route %s\n", args[0]), "", nil
			}, nil
		},
	)
}

func sysctlGetCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Get sysctl parameter",
			Args:    "<parameter parts...>",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			var sb strings.Builder
			err = nsm.exec(nsName, func() error {
				sc := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
				val, err := sc.Read(args)
				if err != nil {
					return fmt.Errorf("failed to read sysctl parameter %q: %w", strings.Join(args, "."), err)
				}
				fmt.Fprintf(&sb, "%s = %s\n", strings.Join(args, "."), strings.TrimSpace(val))

				return nil
			})

			return func(s *script.State) (stdout string, stderr string, err error) {
				return sb.String(), "", nil
			}, err
		},
	)
}

func sysctlSetCmd(nsm *NetNSManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Set sysctl parameter",
			Args:    "<parameter parts...> <value>",
			Flags: func(fs *pflag.FlagSet) {
				fs.String("netns", "", "Execute in the specified network namespace")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, script.ErrUsage
			}

			nsName, err := s.Flags.GetString("netns")
			if err != nil {
				return nil, fmt.Errorf("failed to get netns flag: %w", err)
			}
			if nsName == "" {
				nsName = nsm.currentNamespaceName()
			}

			err = nsm.exec(nsName, func() error {
				sc := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
				if err := sc.Write(args[:len(args)-1], args[len(args)-1]); err != nil {
					return fmt.Errorf("failed to set sysctl parameter %q: %w", strings.Join(args[:len(args)-1], "."), err)
				}

				return nil
			})

			return func(s *script.State) (stdout string, stderr string, err error) {
				return fmt.Sprintf("Set %s = %s\n", strings.Join(args[:len(args)-1], "."), args[len(args)-1]), "", nil
			}, err
		},
	)
}
