// Copyright 2016-2017 Authors of Cilium
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

package endpoint

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/geneve"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/pkg/version"

	log "github.com/Sirupsen/logrus"
)

const (
	// ExecTimeout is the execution timeout to use in join_ep.sh executions
	ExecTimeout = time.Duration(30 * time.Second)
)

func (e *Endpoint) writeL4Map(fw *bufio.Writer, owner Owner, m policy.L4PolicyMap, config string) error {
	array := ""
	index := 0

	for _, l4 := range m {
		// Represents struct l4_allow in bpf/lib/l4.h
		protoNum, err := u8proto.ParseProtocol(l4.Protocol)
		if err != nil {
			return fmt.Errorf("invalid protocol %s", l4.Protocol)
		}

		dport := byteorder.HostToNetwork(uint16(l4.Port))

		redirect := uint16(l4.L7RedirectPort)
		if l4.IsRedirect() && redirect == 0 {
			redirect, err = e.addRedirect(owner, &l4)
			if err != nil {
				return err
			}
		}

		redirect = byteorder.HostToNetwork(redirect).(uint16)
		entry := fmt.Sprintf("%d,%d,%d,%d", index, dport, redirect, protoNum)
		if array != "" {
			array = array + "," + entry
		} else {
			array = entry
		}

		index++
	}

	if array == "" {
		fmt.Fprintf(fw, "#undef %s\n", config)
	} else {
		fmt.Fprintf(fw, "#define %s %s, (), 0\n", config, array)
		fmt.Fprintf(fw, "#define NR_%s %d\n", config, len(m))
	}

	return nil
}

func (e *Endpoint) writeL4Policy(fw *bufio.Writer, owner Owner) error {
	if e.Consumable == nil {
		return nil
	}
	e.Consumable.Mutex.RLock()
	defer e.Consumable.Mutex.RUnlock()
	if e.Consumable.L4Policy == nil {
		return nil
	}

	policy := e.Consumable.L4Policy

	if err := e.writeL4Map(fw, owner, policy.Ingress, "CFG_L4_INGRESS"); err != nil {
		return err
	}

	if err := e.writeL4Map(fw, owner, policy.Egress, "CFG_L4_EGRESS"); err != nil {
		return err
	}

	return nil
}

func (e *Endpoint) writeHeaderfile(prefix string, owner Owner) error {
	headerPath := filepath.Join(prefix, common.CHeaderFileName)
	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	fw := bufio.NewWriter(f)

	fmt.Fprint(fw, "/*\n")

	epStr64, err := e.base64()
	if err == nil {
		var verBase64 string
		verBase64, err = version.Base64()
		if err == nil {
			fmt.Fprintf(fw, " * %s%s:%s\n * \n", common.CiliumCHeaderPrefix,
				verBase64, epStr64)
		}
	}
	if err != nil {
		e.LogStatus(BPF, Warning, fmt.Sprintf("Unable to create a base64: %s", err))
	}

	if e.DockerID == "" {
		fmt.Fprintf(fw, " * Docker Network ID: %s\n", e.DockerNetworkID)
		fmt.Fprintf(fw, " * Docker Endpoint ID: %s\n", e.DockerEndpointID)
	} else {
		fmt.Fprintf(fw, " * Docker Container ID: %s\n", e.DockerID)
	}

	fmt.Fprintf(fw, ""+
		" * MAC: %s\n"+
		" * IPv6 address: %s\n"+
		" * IPv4 address: %s\n"+
		" * Identity: %d\n"+
		" * PolicyMap: %s\n"+
		" * IPv6 Ingress Map: %s\n"+
		" * IPv6 Egress Map: %s\n"+
		" * IPv4 Ingress Map: %s\n"+
		" * IPv4 Egress Map: %s\n"+
		" * NodeMAC: %s\n"+
		" */\n\n",
		e.LXCMAC, e.IPv6.String(), e.IPv4.String(),
		e.GetIdentity(), path.Base(e.PolicyMapPathLocked()),
		path.Base(e.IPv6IngressMapPathLocked()),
		path.Base(e.IPv6EgressMapPathLocked()),
		path.Base(e.IPv4IngressMapPathLocked()),
		path.Base(e.IPv4EgressMapPathLocked()),
		e.NodeMAC)

	fw.WriteString("/*\n")
	fw.WriteString(" * Labels:\n")
	if e.SecLabel != nil {
		if len(e.SecLabel.Labels) == 0 {
			fmt.Fprintf(fw, " * - %s\n", "(no labels)")
		} else {
			for _, v := range e.SecLabel.Labels {
				fmt.Fprintf(fw, " * - %s\n", v)
			}
		}
	}
	fw.WriteString(" */\n\n")

	if !e.PolicyCalculated && e.Opts.IsEnabled(OptionPolicy) && owner.PolicyEnforcement() != NeverEnforce {
		fw.WriteString("#define DROP_ALL\n")
	}

	fw.WriteString(common.FmtDefineAddress("LXC_MAC", e.LXCMAC))
	fw.WriteString(common.FmtDefineComma("LXC_IP", e.IPv6))
	if e.IPv4 != nil {
		fmt.Fprintf(fw, "#define LXC_IPV4 %#x\n", byteorder.HostSliceToNetwork(e.IPv4, reflect.Uint32))
	}
	fw.WriteString(common.FmtDefineAddress("NODE_MAC", e.NodeMAC))

	geneveOpts, err := writeGeneve(prefix, e)
	if err != nil {
		return err
	}
	fw.WriteString(common.FmtDefineArray("GENEVE_OPTS", geneveOpts))

	fmt.Fprintf(fw, "#define LXC_ID %#x\n", e.ID)
	fmt.Fprintf(fw, "#define LXC_ID_NB %#x\n", byteorder.HostToNetwork(e.ID))
	if e.SecLabel != nil {
		fmt.Fprintf(fw, "#define SECLABEL %s\n", e.SecLabel.ID.StringID())
		fmt.Fprintf(fw, "#define SECLABEL_NB %#x\n", byteorder.HostToNetwork(e.SecLabel.ID.Uint32()))
	} else {
		invalid := policy.InvalidIdentity
		fmt.Fprintf(fw, "#define SECLABEL %s\n", invalid.StringID())
		fmt.Fprintf(fw, "#define SECLABEL_NB %#x\n", byteorder.HostToNetwork(invalid.Uint32()))
	}
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", path.Base(e.PolicyMapPathLocked()))
	if e.L3Policy != nil {
		fmt.Fprintf(fw, "#define LPM_MAP_VALUE_SIZE %s\n", strconv.Itoa(cidrmap.LPM_MAP_VALUE_SIZE))
		if e.L3Policy.Ingress.IPv6Count > 0 {
			fmt.Fprintf(fw, "#define CIDR6_INGRESS_MAP %s\n", path.Base(e.IPv6IngressMapPathLocked()))
		}
		if e.L3Policy.Egress.IPv6Count > 0 {
			fmt.Fprintf(fw, "#define CIDR6_EGRESS_MAP %s\n", path.Base(e.IPv6EgressMapPathLocked()))
		}
		if e.L3Policy.Ingress.IPv4Count > 0 {
			fmt.Fprintf(fw, "#define CIDR4_INGRESS_MAP %s\n", path.Base(e.IPv4IngressMapPathLocked()))
		}
		if e.L3Policy.Egress.IPv4Count > 0 {
			fmt.Fprintf(fw, "#define CIDR4_EGRESS_MAP %s\n", path.Base(e.IPv4EgressMapPathLocked()))
		}
	}
	fmt.Fprintf(fw, "#define CALLS_MAP %s\n", path.Base(e.CallsMapPathLocked()))
	if e.Opts.IsEnabled(OptionConntrackLocal) {
		fmt.Fprintf(fw, "#define CT_MAP_SIZE %s\n", strconv.Itoa(ctmap.MapNumEntriesLocal))
		fmt.Fprintf(fw, "#define CT_MAP6 %s\n", ctmap.MapName6+strconv.Itoa(int(e.ID)))
		fmt.Fprintf(fw, "#define CT_MAP4 %s\n", ctmap.MapName4+strconv.Itoa(int(e.ID)))
	} else {
		fmt.Fprintf(fw, "#define CT_MAP_SIZE %s\n", strconv.Itoa(ctmap.MapNumEntriesGlobal))
		fmt.Fprintf(fw, "#define CT_MAP6 %s\n", ctmap.MapName6Global)
		fmt.Fprintf(fw, "#define CT_MAP4 %s\n", ctmap.MapName4Global)
	}

	// Always enable L4 and L3 load balancer for now
	fw.WriteString("#define LB_L3\n")
	fw.WriteString("#define LB_L4\n")

	// Endpoint options
	fw.WriteString(e.Opts.GetFmtList())

	fw.WriteString("#define LXC_PORT_MAPPINGS ")
	for _, m := range e.PortMap {
		// Write mappings directly in network byte order so we don't have
		// to convert it in the fast path
		fmt.Fprintf(fw, "{%#x,%#x},", byteorder.HostToNetwork(m.From), byteorder.HostToNetwork(m.To))
	}
	fw.WriteString("\n")

	if err := e.writeL4Policy(fw, owner); err != nil {
		return err
	}

	if e.L3Policy != nil {
		ipv6Ingress, ipv4Ingress := e.L3Policy.Ingress.ToBPFData()
		ipv6Egress, ipv4Egress := e.L3Policy.Egress.ToBPFData()

		if len(ipv6Ingress) > 0 {
			fw.WriteString("#define CIDR6_INGRESS_MAPPINGS ")
			for _, m := range ipv6Ingress {
				fmt.Fprintf(fw, "%s,", m)
			}
			fw.WriteString("\n")
		}
		if len(ipv6Egress) > 0 {
			fw.WriteString("#define CIDR6_EGRESS_MAPPINGS ")
			for _, m := range ipv6Egress {
				fmt.Fprintf(fw, "%s,", m)
			}
			fw.WriteString("\n")
		}
		if len(ipv4Ingress) > 0 {
			fw.WriteString("#define CIDR4_INGRESS_MAPPINGS ")
			for _, m := range ipv4Ingress {
				fmt.Fprintf(fw, "%s,", m)
			}
			fw.WriteString("\n")
		}
		if len(ipv4Egress) > 0 {
			fw.WriteString("#define CIDR4_EGRESS_MAPPINGS ")
			for _, m := range ipv4Egress {
				fmt.Fprintf(fw, "%s,", m)
			}
			fw.WriteString("\n")
		}
	}

	return fw.Flush()
}

// FIXME: Clean this function up
func writeGeneve(prefix string, e *Endpoint) ([]byte, error) {
	// Write container options values for each available option in
	// bpf/lib/geneve.h
	// GENEVE_CLASS_EXPERIMENTAL, GENEVE_TYPE_SECLABEL
	err := geneve.WriteOpts(filepath.Join(prefix, "geneve_opts.cfg"), "0xffff", "0x1", "4", fmt.Sprintf("%08x", e.GetIdentity()))
	if err != nil {
		return nil, fmt.Errorf("Could not write geneve options %s", err)
	}

	_, rawData, err := geneve.ReadOpts(filepath.Join(prefix, "geneve_opts.cfg"))
	if err != nil {
		return nil, fmt.Errorf("Could not read geneve options %s", err)
	}

	return rawData, nil
}

func (e *Endpoint) runInit(libdir, rundir, prefix, debug string) error {
	args := []string{libdir, rundir, prefix, e.IfName, debug}
	prog := filepath.Join(libdir, "join_ep.sh")

	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		log.Errorf("Command execution failed: Timeout for %s %s", prog, args)
		return ctx.Err()
	}
	if err != nil {
		log.Warningf("Command execution failed: %s", err)
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			log.Warning(scanner.Text())
		}
		return fmt.Errorf("error: %q command output: %q", err, out)
	}

	return nil
}

// regenerateBPF rewrites all headers and updates all BPF maps to reflect the
// specified endpoint.
func (e *Endpoint) regenerateBPF(owner Owner, prefix string) error {
	var err error

	if err = e.writeHeaderfile(prefix, owner); err != nil {
		return fmt.Errorf("unable to write header file: %s", err)
	}

	// If dry mode is enabled, no changes to BPF maps are performed
	if owner.DryModeEnabled() {
		return nil
	}

	// Anything below this point must be reverted upon failure as we are
	// changing live BPF maps
	createdPolicyMap := false
	createdIPv6IngressMap := false
	createdIPv6EgressMap := false
	createdIPv4IngressMap := false
	createdIPv4EgressMap := false
	defer func() {
		if err != nil {
			if createdPolicyMap {
				// Remove policy map file only if it was created
				// in this update cycle
				if e.Consumable != nil {
					e.Consumable.RemoveMap(e.PolicyMap)
				}

				os.RemoveAll(e.PolicyMapPathLocked())
				e.PolicyMap = nil
			}
			if createdIPv6IngressMap {
				e.L3Maps.DestroyBpfMap(IPv6Ingress, e.IPv6IngressMapPathLocked())
			}
			if createdIPv6EgressMap {
				e.L3Maps.DestroyBpfMap(IPv6Egress, e.IPv6EgressMapPathLocked())
			}
			if createdIPv4IngressMap {
				e.L3Maps.DestroyBpfMap(IPv4Ingress, e.IPv4IngressMapPathLocked())
			}
			if createdIPv4EgressMap {
				e.L3Maps.DestroyBpfMap(IPv4Egress, e.IPv4EgressMapPathLocked())
			}
		}
	}()

	if e.PolicyMap == nil {
		e.PolicyMap, createdPolicyMap, err = policymap.OpenMap(e.PolicyMapPathLocked())
		if err != nil {
			return err
		}
	}

	// Only generate & populate policy map if a seclabel and consumer model is set up
	if e.Consumable != nil {
		e.Consumable.AddMap(e.PolicyMap)
	}

	if e.L3Policy != nil {
		if e.L3Policy.Ingress.IPv6Changed {
			if e.L3Policy.Ingress.IPv6Count > 0 &&
				e.L3Maps.ResetBpfMap(IPv6Ingress, e.IPv6IngressMapPathLocked()) == nil {
				createdIPv6IngressMap = true
				e.L3Policy.Ingress.PopulateBPF(e.L3Maps[IPv6Ingress])
			} else {
				e.L3Maps.DestroyBpfMap(IPv6Ingress, e.IPv6IngressMapPathLocked())
			}
		}
		if e.L3Policy.Egress.IPv6Changed {
			if e.L3Policy.Egress.IPv6Count > 0 &&
				e.L3Maps.ResetBpfMap(IPv6Egress, e.IPv6EgressMapPathLocked()) == nil {
				createdIPv6EgressMap = true
				e.L3Policy.Egress.PopulateBPF(e.L3Maps[IPv6Egress])
			} else {
				e.L3Maps.DestroyBpfMap(IPv6Egress, e.IPv6EgressMapPathLocked())
			}
		}

		if e.L3Policy.Ingress.IPv4Changed {
			if e.L3Policy.Ingress.IPv4Count > 0 &&
				e.L3Maps.ResetBpfMap(IPv4Ingress, e.IPv4IngressMapPathLocked()) == nil {
				createdIPv4IngressMap = true
				e.L3Policy.Ingress.PopulateBPF(e.L3Maps[IPv4Ingress])
			} else {
				e.L3Maps.DestroyBpfMap(IPv4Ingress, e.IPv4IngressMapPathLocked())
			}
		}
		if e.L3Policy.Egress.IPv4Changed {
			if e.L3Policy.Egress.IPv4Count > 0 &&
				e.L3Maps.ResetBpfMap(IPv4Egress, e.IPv4EgressMapPathLocked()) == nil {
				createdIPv4EgressMap = true
				e.L3Policy.Egress.PopulateBPF(e.L3Maps[IPv4Egress])
			} else {
				e.L3Maps.DestroyBpfMap(IPv4Egress, e.IPv4EgressMapPathLocked())
			}
		}
	}

	libdir := owner.GetBpfDir()
	rundir := owner.GetStateDir()
	debug := strconv.FormatBool(owner.DebugEnabled())

	if err = e.runInit(libdir, rundir, prefix, debug); err != nil {
		return err
	}

	// The last operation hooks the endpoint into the endpoint table and exposes it
	err = lxcmap.WriteEndpoint(e)

	// Mark the endpoint to be running the policy revision it was
	// compiled for
	if err == nil {
		e.PolicyRevision = e.NextPolicyRevision
	}

	return err
}
