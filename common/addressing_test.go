package common

import (
	"bytes"
	"net"
	"testing"
)

var (
	EpAddr   = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11}
	NodeAddr = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0}
)

func TestEpAddrEndpointAddress(t *testing.T) {
	if !ValidEndpointAddress(EpAddr) {
		t.Fatalf("unexpected invalid EP address %s", EpAddr.String())
	}

	if ValidEndpointAddress(NodeAddr) {
		t.Fatalf("unexpected valid node address %s", NodeAddr.String())
	}
}

func TestNodeAddrEndpointAddress(t *testing.T) {
	if ValidNodeAddress(EpAddr) {
		t.Fatalf("unexpected valid EP address %s", EpAddr.String())
	}

	if !ValidNodeAddress(NodeAddr) {
		t.Fatalf("unexpected invalid node address %s", NodeAddr.String())
	}
}

func TestMapEndpointToNode(t *testing.T) {

	node := MapEndpointToNode(EpAddr)

	if bytes.Compare(node, NodeAddr) != 0 {
		t.Fatalf("MapEndpointToNode failed: %s != %s", node.String(), NodeAddr.String())
	}
}
