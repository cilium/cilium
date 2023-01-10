// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"fmt"
	"strings"
)

const (
	// older versions of the Hubble CLI use a different default path
	hubbleSock = "unix:///var/run/cilium/hubble.sock"
)

// HubbleObserve runs `hubble observe --output=jsonpb <args>`. JSON output is
// enabled such that CmdRes.FilterLines may be used to grep for specific events
// in the output.
func (s *SSHMeta) HubbleObserve(args ...string) *CmdRes {
	argsCoalesced := ""
	if len(args) > 0 {
		argsCoalesced = strings.Join(args, " ")
	}
	hubbleCmd := fmt.Sprintf("hubble observe --server=%q --output=jsonpb %s",
		hubbleSock, argsCoalesced)
	return s.Exec(hubbleCmd)
}

// HubbleObserveFollow runs `hubble observe --follow --output=jsonpb <args>`. The
// command is running in the background and will be terminated only once ctx
// is cancelled. JSON output is enabled such that
// CmdRes.WaitUntilMatchFilterLine may be used to wait for specific events in
// the output.
func (s *SSHMeta) HubbleObserveFollow(ctx context.Context, args ...string) *CmdRes {
	argsCoalesced := ""
	if len(args) > 0 {
		argsCoalesced = strings.Join(args, " ")
	}
	hubbleCmd := fmt.Sprintf("hubble observe --server=%q --follow --output=jsonpb %s",
		hubbleSock, argsCoalesced)
	return s.ExecInBackground(ctx, hubbleCmd)
}
