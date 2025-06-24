// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

// Methods in this file are only used on Linux paired with the MonitorEvent interface.

// Dump prints the message according to the verbosity level specified
func (n *AgentNotify) Dump(args *DumpArgs) {
	if args.Verbosity == JSON {
		fmt.Fprintln(args.Buf, n.getJSON())
	} else {
		fmt.Fprintf(args.Buf, ">> %s: %s\n", resolveAgentType(n.Type), n.Text)
	}
}

// Decode decodes the message in 'data' into the struct.
func (a *AgentNotify) Decode(data []byte) error {
	buf := bytes.NewBuffer(data[1:])
	dec := gob.NewDecoder(buf)
	return dec.Decode(a)
}

// GetSrc retrieves the source endpoint for the message
func (n *AgentNotify) GetSrc() (src uint16) {
	return 0
}

// GetDst retrieves the destination endpoint for the message.
func (n *AgentNotify) GetDst() (dst uint16) {
	return 0
}
