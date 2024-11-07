// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safenetlink

import (
	"context"
	"errors"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

const (
	netlinkRetryInterval = 1 * time.Millisecond
	netlinkRetryMax      = 30
)

// WithRetry runs the netlinkFunc. If netlinkFunc returns netlink.ErrDumpInterrupted, the function is retried.
// If success or any other error is returned, WithRetry returns immediately, propagating the error.
func WithRetry(netlinkFunc func() error) error {
	return resiliency.Retry(context.Background(), netlinkRetryInterval, netlinkRetryMax, func(ctx context.Context, retries int) (bool, error) {
		err := netlinkFunc()
		if errors.Is(err, netlink.ErrDumpInterrupted) {
			return false, nil // retry
		}

		return true, err
	})
}

// WithRetryResult works like WithRetry, but allows netlinkFunc to have a return value besides the error
func WithRetryResult[T any](netlinkFunc func() (T, error)) (out T, err error) {
	err = WithRetry(func() error {
		out, err = netlinkFunc()
		return err
	})
	return out, err
}

// AddrList wraps netlink.AddrList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return WithRetryResult(func() ([]netlink.Addr, error) {
		return netlink.AddrList(link, family)
	})
}

// BridgeVlanList wraps netlink.BridgeVlanList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func BridgeVlanList() (map[int32][]*nl.BridgeVlanInfo, error) {
	return WithRetryResult(func() (map[int32][]*nl.BridgeVlanInfo, error) {
		return netlink.BridgeVlanList()
	})
}

// ChainList wraps netlink.ChainList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func ChainList(link netlink.Link, parent uint32) ([]netlink.Chain, error) {
	return WithRetryResult(func() ([]netlink.Chain, error) {
		return netlink.ChainList(link, parent)
	})
}

// ClassList wraps netlink.ClassList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func ClassList(link netlink.Link, parent uint32) ([]netlink.Class, error) {
	return WithRetryResult(func() ([]netlink.Class, error) {
		return netlink.ClassList(link, parent)
	})
}

// ConntrackTableList wraps netlink.ConntrackTableList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func ConntrackTableList(table netlink.ConntrackTableType, family netlink.InetFamily) ([]*netlink.ConntrackFlow, error) {
	return WithRetryResult(func() ([]*netlink.ConntrackFlow, error) {
		return netlink.ConntrackTableList(table, family)
	})
}

// DevLinkGetDeviceList wraps netlink.DevLinkGetDeviceList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func DevLinkGetDeviceList() ([]*netlink.DevlinkDevice, error) {
	return WithRetryResult(func() ([]*netlink.DevlinkDevice, error) {
		return netlink.DevLinkGetDeviceList()
	})
}

// DevLinkGetAllPortList wraps netlink.DevLinkGetAllPortList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func DevLinkGetAllPortList() ([]*netlink.DevlinkPort, error) {
	return WithRetryResult(func() ([]*netlink.DevlinkPort, error) {
		return netlink.DevLinkGetAllPortList()
	})
}

// DevlinkGetDeviceParams wraps netlink.DevlinkGetDeviceParams, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func DevlinkGetDeviceParams(bus string, device string) ([]*netlink.DevlinkParam, error) {
	return WithRetryResult(func() ([]*netlink.DevlinkParam, error) {
		return netlink.DevlinkGetDeviceParams(bus, device)
	})
}

// FilterList wraps netlink.FilterList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func FilterList(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
	return WithRetryResult(func() ([]netlink.Filter, error) {
		return netlink.FilterList(link, parent)
	})
}

// FouList wraps netlink.FouList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func FouList(fam int) ([]netlink.Fou, error) {
	return WithRetryResult(func() ([]netlink.Fou, error) {
		return netlink.FouList(fam)
	})
}

// GenlFamilyList wraps netlink.GenlFamilyList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func GenlFamilyList() ([]*netlink.GenlFamily, error) {
	return WithRetryResult(func() ([]*netlink.GenlFamily, error) {
		return netlink.GenlFamilyList()
	})
}

// GTPPDPList wraps netlink.GTPPDPList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func GTPPDPList() ([]*netlink.PDP, error) {
	return WithRetryResult(func() ([]*netlink.PDP, error) {
		return netlink.GTPPDPList()
	})
}

// LinkByName wraps netlink.LinkByName, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func LinkByName(name string) (netlink.Link, error) {
	return WithRetryResult(func() (netlink.Link, error) {
		return netlink.LinkByName(name)
	})
}

// LinkByAlias wraps netlink.LinkByAlias, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func LinkByAlias(alias string) (netlink.Link, error) {
	return WithRetryResult(func() (netlink.Link, error) {
		return netlink.LinkByAlias(alias)
	})
}

// LinkList wraps netlink.LinkList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func LinkList() ([]netlink.Link, error) {
	return WithRetryResult(func() ([]netlink.Link, error) {
		return netlink.LinkList()
	})
}

// LinkSubscribeWithOptions wraps netlink.LinkSubscribeWithOptions, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func LinkSubscribeWithOptions(ch chan<- netlink.LinkUpdate, done <-chan struct{}, options netlink.LinkSubscribeOptions) error {
	return WithRetry(func() error {
		return netlink.LinkSubscribeWithOptions(ch, done, options)
	})
}

// NeighList wraps netlink.NeighList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return WithRetryResult(func() ([]netlink.Neigh, error) {
		return netlink.NeighList(linkIndex, family)
	})
}

// NeighProxyList wraps netlink.NeighProxyList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func NeighProxyList(linkIndex, family int) ([]netlink.Neigh, error) {
	return WithRetryResult(func() ([]netlink.Neigh, error) {
		return netlink.NeighProxyList(linkIndex, family)
	})
}

// NeighListExecute wraps netlink.NeighListExecute, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func NeighListExecute(msg netlink.Ndmsg) ([]netlink.Neigh, error) {
	return WithRetryResult(func() ([]netlink.Neigh, error) {
		return netlink.NeighListExecute(msg)
	})
}

// LinkGetProtinfo wraps netlink.LinkGetProtinfo, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func LinkGetProtinfo(link netlink.Link) (netlink.Protinfo, error) {
	return WithRetryResult(func() (netlink.Protinfo, error) {
		return netlink.LinkGetProtinfo(link)
	})
}

// QdiscList wraps netlink.QdiscList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func QdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	return WithRetryResult(func() ([]netlink.Qdisc, error) {
		return netlink.QdiscList(link)
	})
}

// RdmaLinkList wraps netlink.RdmaLinkList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func RdmaLinkList() ([]*netlink.RdmaLink, error) {
	return WithRetryResult(func() ([]*netlink.RdmaLink, error) {
		return netlink.RdmaLinkList()
	})
}

// RdmaLinkByName wraps netlink.RdmaLinkByName, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func RdmaLinkByName(name string) (*netlink.RdmaLink, error) {
	return WithRetryResult(func() (*netlink.RdmaLink, error) {
		return netlink.RdmaLinkByName(name)
	})
}

// RdmaLinkDel wraps netlink.RdmaLinkDel, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func RdmaLinkDel(name string) error {
	return WithRetry(func() error {
		return netlink.RdmaLinkDel(name)
	})
}

// RouteList wraps netlink.RouteList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return WithRetryResult(func() ([]netlink.Route, error) {
		return netlink.RouteList(link, family)
	})
}

// RouteListFiltered wraps netlink.RouteListFiltered, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return WithRetryResult(func() ([]netlink.Route, error) {
		return netlink.RouteListFiltered(family, filter, filterMask)
	})
}

// RouteListFilteredIter wraps netlink.RouteListFilteredIter, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func RouteListFilteredIter(family int, filter *netlink.Route, filterMask uint64, f func(netlink.Route) (cont bool)) error {
	return WithRetry(func() error {
		return netlink.RouteListFilteredIter(family, filter, filterMask, f)
	})
}

// RouteSubscribeWithOptions wraps netlink.RouteSubscribeWithOptions, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func RouteSubscribeWithOptions(ch chan<- netlink.RouteUpdate, done <-chan struct{}, options netlink.RouteSubscribeOptions) error {
	return WithRetry(func() error {
		return netlink.RouteSubscribeWithOptions(ch, done, options)
	})
}

// RuleList wraps netlink.RuleList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func RuleList(family int) ([]netlink.Rule, error) {
	return WithRetryResult(func() ([]netlink.Rule, error) {
		return netlink.RuleList(family)
	})
}

// RuleListFiltered wraps netlink.RuleListFiltered, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func RuleListFiltered(family int, filter *netlink.Rule, filterMask uint64) ([]netlink.Rule, error) {
	return WithRetryResult(func() ([]netlink.Rule, error) {
		return netlink.RuleListFiltered(family, filter, filterMask)
	})
}

// SocketGet wraps netlink.SocketGet, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func SocketGet(local, remote net.Addr) (*netlink.Socket, error) {
	return WithRetryResult(func() (*netlink.Socket, error) {
		return netlink.SocketGet(local, remote)
	})
}

// SocketDiagTCPInfo wraps netlink.SocketDiagTCPInfo, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func SocketDiagTCPInfo(family uint8) ([]*netlink.InetDiagTCPInfoResp, error) {
	return WithRetryResult(func() ([]*netlink.InetDiagTCPInfoResp, error) {
		return netlink.SocketDiagTCPInfo(family)
	})
}

// SocketDiagTCP wraps netlink.SocketDiagTCP, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func SocketDiagTCP(family uint8) ([]*netlink.Socket, error) {
	return WithRetryResult(func() ([]*netlink.Socket, error) {
		return netlink.SocketDiagTCP(family)
	})
}

// SocketDiagUDPInfo wraps netlink.SocketDiagUDPInfo, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func SocketDiagUDPInfo(family uint8) ([]*netlink.InetDiagUDPInfoResp, error) {
	return WithRetryResult(func() ([]*netlink.InetDiagUDPInfoResp, error) {
		return netlink.SocketDiagUDPInfo(family)
	})
}

// SocketDiagUDP wraps netlink.SocketDiagUDP, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func SocketDiagUDP(family uint8) ([]*netlink.Socket, error) {
	return WithRetryResult(func() ([]*netlink.Socket, error) {
		return netlink.SocketDiagUDP(family)
	})
}

// UnixSocketDiagInfo wraps netlink.UnixSocketDiagInfo, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func UnixSocketDiagInfo() ([]*netlink.UnixDiagInfoResp, error) {
	return WithRetryResult(func() ([]*netlink.UnixDiagInfoResp, error) {
		return netlink.UnixSocketDiagInfo()
	})
}

// UnixSocketDiag wraps netlink.UnixSocketDiag, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func UnixSocketDiag() ([]*netlink.UnixSocket, error) {
	return WithRetryResult(func() ([]*netlink.UnixSocket, error) {
		return netlink.UnixSocketDiag()
	})
}

// SocketXDPGetInfo wraps netlink.SocketXDPGetInfo, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func SocketXDPGetInfo(ino uint32, cookie uint64) (*netlink.XDPDiagInfoResp, error) {
	return WithRetryResult(func() (*netlink.XDPDiagInfoResp, error) {
		return netlink.SocketXDPGetInfo(ino, cookie)
	})
}

// SocketDiagXDP wraps netlink.SocketDiagXDP, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func SocketDiagXDP() ([]*netlink.XDPDiagInfoResp, error) {
	return WithRetryResult(func() ([]*netlink.XDPDiagInfoResp, error) {
		return netlink.SocketDiagXDP()
	})
}

// VDPAGetDevList wraps netlink.VDPAGetDevList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func VDPAGetDevList() ([]*netlink.VDPADev, error) {
	return WithRetryResult(func() ([]*netlink.VDPADev, error) {
		return netlink.VDPAGetDevList()
	})
}

// VDPAGetDevConfigList wraps netlink.VDPAGetDevConfigList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func VDPAGetDevConfigList() ([]*netlink.VDPADevConfig, error) {
	return WithRetryResult(func() ([]*netlink.VDPADevConfig, error) {
		return netlink.VDPAGetDevConfigList()
	})
}

// VDPAGetMGMTDevList wraps netlink.VDPAGetMGMTDevList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func VDPAGetMGMTDevList() ([]*netlink.VDPAMGMTDev, error) {
	return WithRetryResult(func() ([]*netlink.VDPAMGMTDev, error) {
		return netlink.VDPAGetMGMTDevList()
	})
}

// XfrmPolicyList wraps netlink.XfrmPolicyList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func XfrmPolicyList(family int) ([]netlink.XfrmPolicy, error) {
	return WithRetryResult(func() ([]netlink.XfrmPolicy, error) {
		return netlink.XfrmPolicyList(family)
	})
}

// XfrmStateList wraps netlink.XfrmStateList, but retries the call automatically
// if netlink.ErrDumpInterrupted is returned
func XfrmStateList(family int) ([]netlink.XfrmState, error) {
	return WithRetryResult(func() ([]netlink.XfrmState, error) {
		return netlink.XfrmStateList(family)
	})
}
