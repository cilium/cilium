// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package testutils

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	"github.com/google/gopacket"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// CreateL3L4Payload assembles a L3/L4 payload for testing purposes
func CreateL3L4Payload(message interface{}, layers ...gopacket.SerializableLayer) ([]byte, error) {
	buf := &bytes.Buffer{}
	switch messageType := message.(type) {
	case monitor.DebugCapture,
		monitor.DropNotify,
		monitor.PolicyVerdictNotify,
		monitor.TraceNotify,
		monitor.TraceNotifyV0,
		monitor.TraceNotifyV1:
		if err := binary.Write(buf, byteorder.Native, message); err != nil {
			return nil, err
		}
	case monitorAPI.AgentNotify:
		buf.WriteByte(byte(monitorAPI.MessageTypeAgent))
		if err := gob.NewEncoder(buf).Encode(message); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported message type %T", messageType)
	}
	packet := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths: true,
	}
	if err := gopacket.SerializeLayers(packet, options, layers...); err != nil {
		return nil, err
	}
	if _, err := buf.Write(packet.Bytes()); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// MustCreateL3L4Payload wraps CreateL3L4Payload, but panics on error
func MustCreateL3L4Payload(message interface{}, layers ...gopacket.SerializableLayer) []byte {
	payload, err := CreateL3L4Payload(message, layers...)
	if err != nil {
		panic(err)
	}
	return payload
}
