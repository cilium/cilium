// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//go:build openbsd
// +build openbsd

package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/osrg/gobgp/v3/pkg/log"
)

const (
	PF_KEY_V2 = 2

	SADB_X_SATYPE_TCPSIGNATURE = 8

	SADB_EXT_SA          = 1
	SADB_EXT_ADDRESS_SRC = 5
	SADB_EXT_ADDRESS_DST = 6
	SADB_EXT_KEY_AUTH    = 8
	SADB_EXT_SPIRANGE    = 16

	SADB_GETSPI = 1
	SADB_UPDATE = 2
	SADB_DELETE = 4

	SADB_X_EALG_AES = 12

	SADB_SASTATE_MATURE = 1
)

type sadbMsg struct {
	sadbMsgVersion  uint8
	sadbMsgType     uint8
	sadbMsgErrno    uint8
	sadbMsgSatype   uint8
	sadbMsgLen      uint16
	sadbMsgReserved uint16
	sadbMsgSeq      uint32
	sadbMsgPid      uint32
}

func (s *sadbMsg) DecodeFromBytes(data []byte) error {
	if len(data) < SADB_MSG_SIZE {
		return fmt.Errorf("too short for sadbMsg %d", len(data))
	}
	s.sadbMsgVersion = data[0]
	s.sadbMsgType = data[1]
	s.sadbMsgErrno = data[2]
	s.sadbMsgSatype = data[3]
	s.sadbMsgLen = binary.LittleEndian.Uint16(data[4:6])
	s.sadbMsgSeq = binary.LittleEndian.Uint32(data[8:12])
	s.sadbMsgPid = binary.LittleEndian.Uint32(data[12:16])
	return nil
}

type sadbSpirange struct {
	sadbSpirangeLen      uint16
	sadbSpirangeExttype  uint16
	sadbSpirangeMin      uint32
	sadbSpirangeMax      uint32
	sadbSpirangeReserved uint32
}

type sadbAddress struct {
	sadbAddressLen      uint16
	sadbAddressExttype  uint16
	sadbAddressReserved uint32
}

type sadbExt struct {
	sadbExtLen  uint16
	sadbExtType uint16
}

type sadbSa struct {
	sadbSaLen     uint16
	sadbSaExttype uint16
	sadbSaSpi     uint32
	sadbSaReplay  uint8
	sadbSaState   uint8
	sadbSaAuth    uint8
	sadbSaEncrypt uint8
	sadbSaFlags   uint32
}

type sadbKey struct {
	sadbKeyLen      uint16
	sadbKeyExttype  uint16
	sadbKeyBits     uint16
	sadbKeyReserved uint16
}

const (
	SADB_MSG_SIZE      = int(unsafe.Sizeof(sadbMsg{}))
	SADB_SPIRANGE_SIZE = int(unsafe.Sizeof(sadbSpirange{}))
	SADB_ADDRESS_SIZE  = int(unsafe.Sizeof(sadbAddress{}))
	SADB_SA_SIZE       = int(unsafe.Sizeof(sadbSa{}))
	SADB_KEY_SIZE      = int(unsafe.Sizeof(sadbKey{}))
)

type sockaddrIn struct {
	ssLen    uint8
	ssFamily uint8
	ssPort   uint16
	ssAddr   uint32
	pad      [8]byte
}

func newSockaddrIn(addr string) sockaddrIn {
	if len(addr) == 0 {
		return sockaddrIn{
			ssLen: 16,
		}
	}
	v := net.ParseIP(addr).To4()
	return sockaddrIn{
		ssAddr:   uint32(v[3])<<24 | uint32(v[2])<<16 | uint32(v[1])<<8 | uint32(v[0]),
		ssLen:    16,
		ssFamily: syscall.AF_INET,
	}
}

func roundUp(v int) int {
	if v%8 != 0 {
		v += 8 - v%8
	}
	return v
}

func b(p unsafe.Pointer, length int) []byte {
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = *(*byte)(p)
		p = unsafe.Pointer(uintptr(p) + 1)
	}
	return buf
}

var seq uint32
var fd int

var spiInMap map[string]uint32 = map[string]uint32{}
var spiOutMap map[string]uint32 = map[string]uint32{}

func pfkeyReply() (spi uint32, err error) {
	buf := make([]byte, SADB_MSG_SIZE)
	if count, _, _, _, _ := syscall.Recvmsg(fd, buf, nil, syscall.MSG_PEEK); count != len(buf) {
		return spi, fmt.Errorf("incomplete sadb msg %d %d", len(buf), count)
	}
	h := sadbMsg{}
	h.DecodeFromBytes(buf)
	if h.sadbMsgErrno != 0 {
		return spi, fmt.Errorf("sadb msg reply error %d", h.sadbMsgErrno)
	}

	if h.sadbMsgSeq != seq {
		return spi, fmt.Errorf("sadb msg sequence doesn't match %d %d", h.sadbMsgSeq, seq)
	}

	if h.sadbMsgPid != uint32(os.Getpid()) {
		return spi, fmt.Errorf("sadb msg pid doesn't match %d %d", h.sadbMsgPid, os.Getpid())
	}

	buf = make([]byte, int(8*h.sadbMsgLen))
	if count, _, _, _, _ := syscall.Recvmsg(fd, buf, nil, 0); count != len(buf) {
		return spi, fmt.Errorf("incomplete sadb msg body %d %d", len(buf), count)
	}

	buf = buf[SADB_MSG_SIZE:]

	for len(buf) >= 4 {
		l := binary.LittleEndian.Uint16(buf[0:2]) * 8
		t := binary.LittleEndian.Uint16(buf[2:4])
		if t == SADB_EXT_SA {
			return binary.LittleEndian.Uint32(buf[4:8]), nil
		}

		if len(buf) <= int(l) {
			break
		}
		buf = buf[l:]
	}
	return spi, err
}

func sendSadbMsg(msg *sadbMsg, body []byte) (err error) {
	if fd == 0 {
		fd, err = syscall.Socket(syscall.AF_KEY, syscall.SOCK_RAW, PF_KEY_V2)
		if err != nil {
			return err
		}
	}

	seq++
	msg.sadbMsgSeq = seq
	msg.sadbMsgLen = uint16((len(body) + SADB_MSG_SIZE) / 8)

	buf := append(b(unsafe.Pointer(msg), SADB_MSG_SIZE), body...)

	r, err := syscall.Write(fd, buf)
	if r != len(buf) {
		return fmt.Errorf("short write %d %d", r, len(buf))
	}
	return err
}

func rfkeyRequest(msgType uint8, src, dst string, spi uint32, key string) error {
	h := sadbMsg{
		sadbMsgVersion: PF_KEY_V2,
		sadbMsgType:    msgType,
		sadbMsgSatype:  SADB_X_SATYPE_TCPSIGNATURE,
		sadbMsgPid:     uint32(os.Getpid()),
	}

	ssrc := newSockaddrIn(src)
	sa_src := sadbAddress{
		sadbAddressExttype: SADB_EXT_ADDRESS_SRC,
		sadbAddressLen:     uint16(SADB_ADDRESS_SIZE+roundUp(int(ssrc.ssLen))) / 8,
	}

	sdst := newSockaddrIn(dst)
	sa_dst := sadbAddress{
		sadbAddressExttype: SADB_EXT_ADDRESS_DST,
		sadbAddressLen:     uint16(SADB_ADDRESS_SIZE+roundUp(int(sdst.ssLen))) / 8,
	}

	buf := make([]byte, 0)
	switch msgType {
	case SADB_UPDATE, SADB_DELETE:
		sa := sadbSa{
			sadbSaLen:     uint16(SADB_SA_SIZE / 8),
			sadbSaExttype: SADB_EXT_SA,
			sadbSaSpi:     spi,
			sadbSaState:   SADB_SASTATE_MATURE,
			sadbSaEncrypt: SADB_X_EALG_AES,
		}
		buf = append(buf, b(unsafe.Pointer(&sa), SADB_SA_SIZE)...)
	case SADB_GETSPI:
		spirange := sadbSpirange{
			sadbSpirangeLen:     uint16(SADB_SPIRANGE_SIZE) / 8,
			sadbSpirangeExttype: SADB_EXT_SPIRANGE,
			sadbSpirangeMin:     0x100,
			sadbSpirangeMax:     0xffffffff,
		}
		buf = append(buf, b(unsafe.Pointer(&spirange), SADB_SPIRANGE_SIZE)...)
	}

	buf = append(buf, b(unsafe.Pointer(&sa_dst), SADB_ADDRESS_SIZE)...)
	buf = append(buf, b(unsafe.Pointer(&sdst), roundUp(int(sdst.ssLen)))...)
	buf = append(buf, b(unsafe.Pointer(&sa_src), SADB_ADDRESS_SIZE)...)
	buf = append(buf, b(unsafe.Pointer(&ssrc), roundUp(int(ssrc.ssLen)))...)

	switch msgType {
	case SADB_UPDATE:
		keylen := roundUp(len(key))
		sa_akey := sadbKey{
			sadbKeyLen:     uint16((SADB_KEY_SIZE + keylen) / 8),
			sadbKeyExttype: SADB_EXT_KEY_AUTH,
			sadbKeyBits:    uint16(len(key) * 8),
		}
		k := []byte(key)
		if pad := keylen - len(k); pad != 0 {
			k = append(k, make([]byte, pad)...)
		}
		buf = append(buf, b(unsafe.Pointer(&sa_akey), SADB_KEY_SIZE)...)
		buf = append(buf, k...)
	}

	return sendSadbMsg(&h, buf)
}

func saAdd(address, key string) error {
	f := func(src, dst string) error {
		if err := rfkeyRequest(SADB_GETSPI, src, dst, 0, ""); err != nil {
			return err
		}
		spi, err := pfkeyReply()
		if err != nil {
			return err
		}
		if src == "" {
			spiOutMap[address] = spi
		} else {
			spiInMap[address] = spi
		}

		if err := rfkeyRequest(SADB_UPDATE, src, dst, spi, key); err != nil {
			return err
		}
		_, err = pfkeyReply()
		return err
	}

	if err := f(address, ""); err != nil {
		return err
	}

	return f("", address)
}

func saDelete(address string) error {
	if spi, y := spiInMap[address]; y {
		if err := rfkeyRequest(SADB_DELETE, address, "", spi, ""); err != nil {
			return fmt.Errorf("failed to delete md5 for incoming: %s", err)
		}
	} else {
		return fmt.Errorf("can't find spi for md5 for incoming")
	}

	if spi, y := spiOutMap[address]; y {
		if err := rfkeyRequest(SADB_DELETE, "", address, spi, ""); err != nil {
			return fmt.Errorf("failed to delete md5 for outgoing: %s", err)
		}
	} else {
		return fmt.Errorf("can't find spi for md5 for outgoing")
	}
	return nil
}

const (
	tcpMD5SIG       = 0x4 // TCP MD5 Signature (RFC2385)
	ipv6MinHopCount = 73  // Generalized TTL Security Mechanism (RFC5082)
)

func setsockoptTcpMD5Sig(sc syscall.RawConn, address string, key string) error {
	if err := setsockOptInt(sc, syscall.IPPROTO_TCP, tcpMD5SIG, 1); err != nil {
		return err
	}
	if len(key) > 0 {
		return saAdd(address, key)
	}
	return saDelete(address)
}

func setTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	sc, err := l.SyscallConn()
	if err != nil {
		return err
	}
	return setsockoptTcpMD5Sig(sc, address, key)
}

func setTCPTTLSockopt(conn *net.TCPConn, ttl int) error {
	family := extractFamilyFromTCPConn(conn)
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return setsockoptIpTtl(sc, family, ttl)
}

func setTCPMinTTLSockopt(conn *net.TCPConn, ttl int) error {
	family := extractFamilyFromTCPConn(conn)
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	level := syscall.IPPROTO_IP
	name := syscall.IP_MINTTL
	if family == syscall.AF_INET6 {
		level = syscall.IPPROTO_IPV6
		name = ipv6MinHopCount
	}
	return setsockOptInt(sc, level, name, ttl)
}

func setBindToDevSockopt(sc syscall.RawConn, device string) error {
	return fmt.Errorf("binding connection to a device is not supported")
}

func dialerControl(logger log.Logger, network, address string, c syscall.RawConn, ttl, minTtl uint8, password string, bindInterface string) error {
	if password != "" {
		logger.Warn("setting md5 for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address})
	}
	if ttl != 0 {
		logger.Warn("setting ttl for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address})
	}
	if minTtl != 0 {
		logger.Warn("setting min ttl for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address})
	}
	return nil
}
