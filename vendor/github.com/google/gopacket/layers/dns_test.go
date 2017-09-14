// Copyright 2012, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket"
)

// testPacketDNSRegression is the packet:
//   11:08:05.708342 IP 109.194.160.4.57766 > 95.211.92.14.53: 63000% [1au] A? picslife.ru. (40)
//      0x0000:  0022 19b6 7e22 000f 35bb 0b40 0800 4500  ."..~"..5..@..E.
//      0x0010:  0044 89c4 0000 3811 2f3d 6dc2 a004 5fd3  .D....8./=m..._.
//      0x0020:  5c0e e1a6 0035 0030 a597 f618 0010 0001  \....5.0........
//      0x0030:  0000 0000 0001 0870 6963 736c 6966 6502  .......picslife.
//      0x0040:  7275 0000 0100 0100 0029 1000 0000 8000  ru.......)......
//      0x0050:  0000                                     ..
var testPacketDNSRegression = []byte{
	0x00, 0x22, 0x19, 0xb6, 0x7e, 0x22, 0x00, 0x0f, 0x35, 0xbb, 0x0b, 0x40, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x44, 0x89, 0xc4, 0x00, 0x00, 0x38, 0x11, 0x2f, 0x3d, 0x6d, 0xc2, 0xa0, 0x04, 0x5f, 0xd3,
	0x5c, 0x0e, 0xe1, 0xa6, 0x00, 0x35, 0x00, 0x30, 0xa5, 0x97, 0xf6, 0x18, 0x00, 0x10, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x70, 0x69, 0x63, 0x73, 0x6c, 0x69, 0x66, 0x65, 0x02,
	0x72, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00,
	0x00, 0x00,
}

func TestPacketDNSRegression(t *testing.T) {
	p := gopacket.NewPacket(testPacketDNSRegression, LinkTypeEthernet, testDecodeOptions)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeUDP, LayerTypeDNS}, t)
}
func BenchmarkDecodePacketDNSRegression(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketDNSRegression, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// response to `dig TXT google.com` over IPv4 link:
var testParseDNSTypeTXTValue = `v=spf1 include:_spf.google.com ~all`
var testParseDNSTypeTXT = []byte{
	0x02, 0x00, 0x00, 0x00, // PF_INET
	0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x39, 0x11, 0x64, 0x98, 0xd0, 0x43, 0xde, 0xde,
	0x0a, 0xba, 0x23, 0x06, 0x00, 0x35, 0x81, 0xb2, 0x00, 0x5f, 0xdc, 0xb5, 0x98, 0x71, 0x81, 0x80,
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
	0x63, 0x6f, 0x6d, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00,
	0x0e, 0x10, 0x00, 0x24, 0x23, 0x76, 0x3d, 0x73, 0x70, 0x66, 0x31, 0x20, 0x69, 0x6e, 0x63, 0x6c,
	0x75, 0x64, 0x65, 0x3a, 0x5f, 0x73, 0x70, 0x66, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x63, 0x6f, 0x6d, 0x20, 0x7e, 0x61, 0x6c, 0x6c, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00,
}

func TestParseDNSTypeTXT(t *testing.T) {
	p := gopacket.NewPacket(testParseDNSTypeTXT, LinkTypeNull, testDecodeOptions)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeLoopback, LayerTypeIPv4, LayerTypeUDP, LayerTypeDNS}, t)
	answers := p.Layer(LayerTypeDNS).(*DNS).Answers
	if len(answers) != 1 {
		t.Error("Failed to parse 1 DNS answer")
	}
	if len(answers[0].TXTs) != 1 {
		t.Error("Failed to parse 1 TXT record")
	}
	txt := string(answers[0].TXTs[0])
	if txt != testParseDNSTypeTXTValue {
		t.Errorf("Incorrect TXT value, expected %q, got %q", testParseDNSTypeTXTValue, txt)
	}
}

func testQuestionEqual(t *testing.T, i int, exp, got DNSQuestion) {
	if !bytes.Equal(exp.Name, got.Name) {
		t.Errorf("expected Questions[%d].Name = %v, got %v", i, string(exp.Name), string(got.Name))
	}
	if exp.Type != got.Type {
		t.Errorf("expected Questions[%d].Type = %v, got %v", i, exp.Type, got.Type)
	}
	if exp.Class != got.Class {
		t.Errorf("expected Questions[%d].Class = %v, got %v", i, exp.Class, got.Class)
	}
}

func testResourceEqual(t *testing.T, i int, name string, exp, got DNSResourceRecord) {
	if !bytes.Equal(exp.Name, got.Name) {
		t.Errorf("expected %s[%d].Name = %v, got %v", name, i, string(exp.Name), string(got.Name))
	}

	if exp.Type != got.Type {
		t.Errorf("expected %s[%d].Type = %v, got %v", name, i, exp.Type, got.Type)
	}

	if exp.Class != got.Class {
		t.Errorf("expected %s[%d].Class = %v, got %v", name, i, exp.Class, got.Class)
	}

	if exp.TTL != got.TTL {
		t.Errorf("expected %s[%d].TTL = %v, got %v", name, i, exp.TTL, got.TTL)
	}
	if exp.DataLength != got.DataLength {
		t.Errorf("expected %s[%d].DataLength = %v, got %v", name, i, exp.DataLength, got.DataLength)
	}

	// we don't check .Data

	if !exp.IP.Equal(got.IP) {
		t.Errorf("expected %s[%d].IP = %v, got %v", name, i, exp.IP, got.IP)
	}
	if !bytes.Equal(exp.NS, got.NS) {
		t.Errorf("expected %s[%d].NS = %v, got %v", name, i, exp.NS, got.NS)
	}
	if !bytes.Equal(exp.CNAME, got.CNAME) {
		t.Errorf("expected %s[%d].CNAME = %v, got %v", name, i, exp.CNAME, got.CNAME)
	}
	if !bytes.Equal(exp.PTR, got.PTR) {
		t.Errorf("expected %s[%d].PTR = %v, got %v", name, i, exp.PTR, got.PTR)
	}
	if len(exp.TXTs) != len(got.TXTs) {
		t.Errorf("expected %s[%d].TXTs = %v, got %v", name, i, exp.TXTs, got.TXTs)
	}
	for j := range exp.TXTs {
		if !bytes.Equal(exp.TXTs[j], got.TXTs[j]) {
			t.Errorf("expected %s[%d].TXTs[%d] = %v, got %v", name, i, j, exp.TXTs[j], got.TXTs[j])
		}
	}

	// SOA
	if !bytes.Equal(exp.SOA.MName, got.SOA.MName) {
		t.Errorf("expected %s[%d].SOA.MName = %v, got %v", name, i, exp.SOA.MName, got.SOA.MName)
	}
	if !bytes.Equal(exp.SOA.RName, got.SOA.RName) {
		t.Errorf("expected %s[%d].SOA.RName = %v, got %v", name, i, exp.SOA.RName, got.SOA.RName)
	}
	if exp.SOA.Serial != got.SOA.Serial {
		t.Errorf("expected %s[%d].SOA.Serial = %v, got %v", name, i, exp.SOA.Serial, got.SOA.Serial)
	}
	if exp.SOA.Refresh != got.SOA.Refresh {
		t.Errorf("expected %s[%d].SOA.Refresh = %v, got %v", name, i, exp.SOA.Refresh, got.SOA.Refresh)
	}
	if exp.SOA.Retry != got.SOA.Retry {
		t.Errorf("expected %s[%d].SOA.Retry = %v, got %v", name, i, exp.SOA.Retry, got.SOA.Retry)
	}
	if exp.SOA.Expire != got.SOA.Expire {
		t.Errorf("expected %s[%d].SOA.Expire = %v, got %v", name, i, exp.SOA.Expire, got.SOA.Expire)
	}
	if exp.SOA.Minimum != got.SOA.Minimum {
		t.Errorf("expected %s[%d].SOA.Minimum = %v, got %v", name, i, exp.SOA.Minimum, got.SOA.Minimum)
	}

	// SRV
	if !bytes.Equal(exp.SRV.Name, got.SRV.Name) {
		t.Errorf("expected %s[%d].SRV.Name = %v, got %v", name, i, exp.SRV.Name, got.SRV.Name)
	}
	if exp.SRV.Weight != got.SRV.Weight {
		t.Errorf("expected %s[%d].SRV.Weight = %v, got %v", name, i, exp.SRV.Weight, got.SRV.Weight)
	}
	if exp.SRV.Port != got.SRV.Port {
		t.Errorf("expected %s[%d].SRV.Port = %v, got %v", name, i, exp.SRV.Port, got.SRV.Port)
	}
	// MX
	if !bytes.Equal(exp.MX.Name, got.MX.Name) {
		t.Errorf("expected %s[%d].MX.Name = %v, got %v", name, i, exp.MX.Name, got.MX.Name)
	}
	if exp.MX.Preference != got.MX.Preference {
		t.Errorf("expected %s[%d].MX.Preference = %v, got %v", name, i, exp.MX.Preference, got.MX.Preference)
	}
}

func testDNSEqual(t *testing.T, exp, got *DNS) {
	if exp.ID != got.ID {
		t.Errorf("expected ID = %v, got %v", exp.ID, got.ID)
	}
	if exp.AA != got.AA {
		t.Errorf("expected AA = %v, got %v", exp.AA, got.AA)
	}
	if exp.OpCode != got.OpCode {
		t.Errorf("expected OpCode = %v, got %v", exp.OpCode, got.OpCode)
	}
	if exp.AA != got.AA {
		t.Errorf("expected AA = %v, got %v", exp.AA, got.AA)
	}
	if exp.TC != got.TC {
		t.Errorf("expected TC = %v, got %v", exp.TC, got.TC)
	}
	if exp.RD != got.RD {
		t.Errorf("expected RD = %v, got %v", exp.RD, got.RD)
	}
	if exp.RA != got.RA {
		t.Errorf("expected RA = %v, got %v", exp.RA, got.RA)
	}
	if exp.Z != got.Z {
		t.Errorf("expected Z = %v, got %v", exp.Z, got.Z)
	}
	if exp.ResponseCode != got.ResponseCode {
		t.Errorf("expected ResponseCode = %v, got %v", exp.ResponseCode, got.ResponseCode)
	}
	if exp.QDCount != got.QDCount {
		t.Errorf("expected QDCount = %v, got %v", exp.QDCount, got.QDCount)
	}
	if exp.ANCount != got.ANCount {
		t.Errorf("expected ANCount = %v, got %v", exp.ANCount, got.ANCount)
	}
	if exp.ANCount != got.ANCount {
		t.Errorf("expected ANCount = %v, got %v", exp.ANCount, got.ANCount)
	}
	if exp.NSCount != got.NSCount {
		t.Errorf("expected NSCount = %v, got %v", exp.NSCount, got.NSCount)
	}
	if exp.ARCount != got.ARCount {
		t.Errorf("expected ARCount = %v, got %v", exp.ARCount, got.ARCount)
	}

	if len(exp.Questions) != len(got.Questions) {
		t.Errorf("expected %d Questions, got %d", len(exp.Questions), len(got.Questions))
	}
	for i := range exp.Questions {
		testQuestionEqual(t, i, exp.Questions[i], got.Questions[i])
	}

	if len(exp.Answers) != len(got.Answers) {
		t.Errorf("expected %d Answers, got %d", len(exp.Answers), len(got.Answers))
	}
	for i := range exp.Answers {
		testResourceEqual(t, i, "Answers", exp.Answers[i], got.Answers[i])
	}

	if len(exp.Authorities) != len(got.Authorities) {
		t.Errorf("expected %d Answers, got %d", len(exp.Authorities), len(got.Authorities))
	}
	for i := range exp.Authorities {
		testResourceEqual(t, i, "Authorities", exp.Authorities[i], got.Authorities[i])
	}

	if len(exp.Additionals) != len(got.Additionals) {
		t.Errorf("expected %d Additionals, got %d", len(exp.Additionals), len(got.Additionals))
	}
	for i := range exp.Additionals {
		testResourceEqual(t, i, "Additionals", exp.Additionals[i], got.Additionals[i])
	}
}

func TestDNSEncodeQuery(t *testing.T) {
	dns := &DNS{ID: 1234, OpCode: DNSOpCodeQuery, RD: true}
	dns.Questions = append(dns.Questions,
		DNSQuestion{
			Name:  []byte("example1.com"),
			Type:  DNSTypeA,
			Class: DNSClassIN,
		})

	dns.Questions = append(dns.Questions,
		DNSQuestion{
			Name:  []byte("example2.com"),
			Type:  DNSTypeA,
			Class: DNSClassIN,
		})

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, dns)
	if err != nil {
		t.Fatal(err)
	}
	if int(dns.QDCount) != len(dns.Questions) {
		t.Errorf("fix lengths did not adjust QDCount, expected %d got %d", len(dns.Questions), dns.QDCount)
	}

	p2 := gopacket.NewPacket(buf.Bytes(), LayerTypeDNS, testDecodeOptions)
	dns2 := p2.Layer(LayerTypeDNS).(*DNS)
	testDNSEqual(t, dns, dns2)
}

func TestDNSEncodeResponse(t *testing.T) {
	dns := &DNS{ID: 1234, QR: true, OpCode: DNSOpCodeQuery,
		AA: true, RD: true, RA: true}
	dns.Questions = append(dns.Questions,
		DNSQuestion{
			Name:  []byte("example1.com"),
			Type:  DNSTypeA,
			Class: DNSClassIN,
		})
	dns.Questions = append(dns.Questions,
		DNSQuestion{
			Name:  []byte("www.example2.com"),
			Type:  DNSTypeAAAA,
			Class: DNSClassIN,
		})

	dns.Answers = append(dns.Answers,
		DNSResourceRecord{
			Name:  []byte("example1.com"),
			Type:  DNSTypeA,
			Class: DNSClassIN,
			TTL:   1024,
			IP:    net.IP([]byte{1, 2, 3, 4}),
		})

	dns.Answers = append(dns.Answers,
		DNSResourceRecord{
			Name:  []byte("www.example2.com"),
			Type:  DNSTypeAAAA,
			Class: DNSClassIN,
			TTL:   1024,
			IP:    net.IP([]byte{5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4}),
		})

	dns.Answers = append(dns.Answers,
		DNSResourceRecord{
			Name:  []byte("www.example2.com"),
			Type:  DNSTypeCNAME,
			Class: DNSClassIN,
			TTL:   1024,
			CNAME: []byte("example2.com"),
		})

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, dns)
	if err != nil {
		t.Fatal(err)
	}
	if int(dns.ANCount) != len(dns.Answers) {
		t.Errorf("fix lengths did not adjust ANCount, expected %d got %d", len(dns.Answers), dns.ANCount)
	}
	for i, a := range dns.Answers {
		if a.DataLength == 0 {
			t.Errorf("fix lengths did not adjust Answers[%d].DataLength", i)
		}
	}

	p2 := gopacket.NewPacket(buf.Bytes(), LayerTypeDNS, testDecodeOptions)
	dns2 := p2.Layer(LayerTypeDNS).(*DNS)
	testDNSEqual(t, dns, dns2)
}
