// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package arp

import (
	"bytes"
	"errors"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
)

var (
	ErrNotImplemented = errors.New("not implemented")

	timeout = 1 * time.Second
	retries = 3
)

var defaultSerializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// PingOverLink performs arping request from 'src' IP address to the 'dst' IP address
// over the link 'link' and returns the hardware address (MAC) of the destination
func PingOverLink(link netlink.Link, src net.IP, dst net.IP) (hwAddr net.HardwareAddr, err error) {
	p, err := newPinger(link, src)
	if err != nil {
		return nil, err
	}
	defer p.close()

	for i := 0; i < retries; i++ {
		if err := p.setDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}

		hwAddr, err = p.resolve(dst)
		if err == nil {
			return
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
	}
	return
}

var _ net.Addr = &Addr{}

type Addr struct {
	net.HardwareAddr
}

func (a *Addr) Network() string {
	return "raw"
}

type pinger struct {
	c    net.PacketConn
	ip   net.IP
	link netlink.Link
}

func (p *pinger) close() {
	_ = p.c.Close()
}

func (p *pinger) setDeadline(t time.Time) error {
	return p.c.SetDeadline(t)
}

func (p *pinger) resolve(ip net.IP) (net.HardwareAddr, error) {
	if err := p.request(ip); err != nil {
		return nil, err
	}

	for {
		resp, err := p.read()
		if err != nil {
			return nil, err
		}

		if !(resp.Operation == layers.ARPReply && bytes.Equal(resp.SourceProtAddress, ip.To4()) &&
			bytes.Equal(resp.DstProtAddress, p.ip.To4())) {
			continue
		}

		dstHwAddr := make(net.HardwareAddr, resp.HwAddressSize)
		copy(dstHwAddr, resp.SourceHwAddress)

		return dstHwAddr, nil
	}
}

func (p *pinger) read() (*layers.ARP, error) {
	buf := make([]byte, 128)
	for {
		n, _, err := p.c.ReadFrom(buf)
		if err != nil {
			return nil, err
		}

		arp, err := decodeARPReply(buf, n)
		if err != nil {
			return nil, err
		}

		if arp.Protocol != layers.EthernetTypeIPv4 || arp.ProtAddressSize != 4 {
			continue
		}

		return arp, nil
	}
}

func (p *pinger) request(dstIp net.IP) error {
	req, err := newARPRequest(p.link.Attrs().HardwareAddr, p.ip, layers.EthernetBroadcast, dstIp)
	if err != nil {
		return err
	}

	_, err = p.c.WriteTo(req, &Addr{HardwareAddr: layers.EthernetBroadcast})

	return err
}

func newPinger(link netlink.Link, ip net.IP) (*pinger, error) {
	c, err := listen(link)
	if err != nil {
		return nil, err
	}

	return &pinger{
		c:    c,
		link: link,
		ip:   ip,
	}, nil
}

func decodeARPReply(buf []byte, n int) (*layers.ARP, error) {
	ethernet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.Default)

	arp := &layers.ARP{}
	arpLayer := ethernet.Layer(layers.LayerTypeARP)
	if err := arp.DecodeFromBytes(arpLayer.LayerContents(), gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}

	return arp, nil
}

func newARPRequest(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
	}

	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,

		HwAddressSize:   6,
		ProtAddressSize: 4,
		Operation:       layers.ARPRequest,

		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),

		DstHwAddress:   []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress: []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, defaultSerializeOpts, &ether, &arp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
