//
// Copyright 2016 Authors of Cilium
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
//
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/bpf/ctmap"
	"github.com/cilium/cilium/bpf/policymap"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/urfave/cli"
)

var (
	cliEndpoint cli.Command
)

func init() {
	cliEndpoint = cli.Command{
		Name:  "endpoint",
		Usage: "Manage endpoint operations",
		Subcommands: []cli.Command{
			{
				Name:         "detach",
				Usage:        "Detaches BPF program from endpoint",
				Action:       detachBPF,
				BashComplete: listEndpointsBash,
				ArgsUsage:    "<endpoint>",
				Before:       verifyArguments,
			},
			{
				Name:         "inspect",
				Usage:        "Dumps lxc-info of the given endpoint",
				Action:       inspectEndpoint,
				BashComplete: listEndpointsBash,
				ArgsUsage:    "<endpoint>",
				Before:       verifyArguments,
			},
			{
				Name:         "labels",
				Usage:        "Manage labels endpoint configuration",
				Action:       configLabels,
				BashComplete: listEndpointsBash,
				ArgsUsage:    "<endpoint>",
				Flags: []cli.Flag{
					cli.StringSliceFlag{
						Name: "enable, e",
					},
					cli.StringSliceFlag{
						Name: "disable, d",
					},
					cli.StringSliceFlag{
						Name: "add, a",
					},
					cli.StringSliceFlag{
						Name: "delete, D",
					},
				},
				Before: verifyArguments,
			},
			{
				Name:   "list",
				Usage:  "Dumps a list of all daemon's endpoints",
				Action: dumpEndpoints,
			},
			{
				Name:         "config",
				Usage:        "Manage endpoint configuration",
				Action:       configEndpoint,
				BashComplete: listEndpointsBash,
				ArgsUsage:    "<endpoint> [<option>=(enable|disable) ...]",
				Before:       verifyConfigEndpoint,
			},
			{
				Name:  "policy",
				Usage: "Manage policy status for the given endpoint",
				Subcommands: []cli.Command{
					{
						Name:         "dump",
						Usage:        "Dumps bpf policy-map of the given endpoint",
						Action:       dumpMap,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint>",
						Before:       verifyArguments,
						Flags: []cli.Flag{
							cli.BoolFlag{
								Name:  "id, i",
								Usage: "Don't resolve label's ID",
							},
						},
					},
					{
						Name:         "add",
						Usage:        "Adds an entry to bpf policy-map of the given endpoint",
						Action:       addPolicyKey,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint> <label_id>",
					},
					{
						Name:         "remove",
						Usage:        "Removes an entry from bpf policy-map of the given endpoint",
						Action:       removePolicyKey,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint> <label_id>",
					},
				},
			},
			{
				Name:  "ct",
				Usage: "Manage Connection Tracker",
				Subcommands: []cli.Command{
					{
						Name:         "dump",
						Usage:        "Dumps connection tracking table for given endpoint",
						Action:       dumpCt,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint>",
						Before:       verifyArguments,
					},
				},
			},
			{
				Name:         "recompile",
				Usage:        "Recompiles endpoint's bpf program",
				Action:       recompileBPF,
				BashComplete: listEndpointsBash,
				ArgsUsage:    "<endpoint>",
				Before:       verifyArguments,
			},
		},
	}
}

func verifyArguments(ctx *cli.Context) error {
	ep := ctx.Args().First()
	if ep == "" {
		return fmt.Errorf("Error: empty endpoint")
	}
	if len(ctx.Args()) != 1 {
		return fmt.Errorf("Error: only one endpoint is permited")
	}
	return nil
}

func printEndpointLabels(lbls *labels.OpLabels) {
	log.Debugf("All Labels %#v", *lbls)
	w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)

	for _, v := range lbls.Enabled() {
		text := common.Green("Enabled")
		fmt.Fprintf(w, "%s\t%s\n", v, text)
	}

	for _, v := range lbls.Disabled {
		text := common.Red("Disabled")
		fmt.Fprintf(w, "%s\t%s\n", v, text)
	}
	w.Flush()
}

func configLabels(ctx *cli.Context) {
	_, id, err := endpoint.ValidateID(ctx.Args().First())
	if err != nil {
		Fatalf("%s", err)
	}

	lo := &models.LabelConfigurationModifier{}

	addLabels := labels.ParseStringLabels(ctx.StringSlice("add"))
	if len(addLabels) != 0 {
		lo.Add = addLabels.GetModel()
	}

	deleteLabels := labels.ParseStringLabels(ctx.StringSlice("delete"))
	if len(deleteLabels) != 0 {
		lo.Delete = deleteLabels.GetModel()
	}

	if err := client.EndpointLabelsPut(id, lo); err != nil {
		log.Errorf("Error while modifying labels %s", err)
	}

	if lbls, err := client.EndpointLabelsGet(id); err != nil {
		log.Errorf("Error while getting endpoint labels: %s", err)
	} else {
		printEndpointLabels(labels.NewOplabelsFromModel(lbls))
	}
}

func inspectEndpoint(ctx *cli.Context) {
	_, id, err := endpoint.ValidateID(ctx.Args().First())
	if err != nil {
		Fatalf("%s", err)
	}

	if e, err := client.EndpointGet(id); err != nil {
		Fatalf("Error while inspecting endpoint %s: %s\n", id, err)
	} else if b, err := json.MarshalIndent(e, "", "  "); err != nil {
		Fatalf(err.Error())
	} else {
		fmt.Println(string(b))
	}
}

func listEndpointOptions() {
	for k, s := range endpoint.EndpointOptionLibrary {
		fmt.Printf("%-24s %s\n", k, s.Description)
	}
}

func verifyConfigEndpoint(ctx *cli.Context) error {
	if ctx.Args().First() == "" {
		return fmt.Errorf("Error: Need endpoint ID")
	}
	return nil
}

func configEndpoint(ctx *cli.Context) {
	if ctx.Args().First() == "list" {
		listEndpointOptions()
		return
	}

	_, id, err := endpoint.ValidateID(ctx.Args().First())
	if err != nil {
		Fatalf("%s", err)
	}

	cfg, err := client.EndpointConfigGet(id)
	if err != nil {
		Fatalf("Error while retrieving endpoint %s: %s\n", id, err)
	}

	opts := ctx.Args().Tail()
	if len(opts) == 0 {
		fmt.Printf("%+v\n", cfg)
		return
	}

	epOpts := make(models.ConfigurationMap, len(opts))

	for k := range opts {
		name, value, err := option.ParseOption(opts[k], &endpoint.EndpointOptionLibrary)
		if err != nil {
			Fatalf("%s\n", err)
		}

		if value {
			epOpts[name] = "enabled"
		} else {
			epOpts[name] = "disabled"
		}
	}

	err = client.EndpointConfigPatch(id, epOpts)
	if err != nil {
		Fatalf("Unable to update endpoint %s: %s\n", id, err)
	}
}

func dumpMap(ctx *cli.Context) {
	lbl := ctx.Args().First()
	printIDs := ctx.Bool("id")

	if lbl != "" {
		if id := policy.GetReservedID(lbl); id != policy.ID_UNKNOWN {
			lbl = "reserved_" + strconv.FormatUint(uint64(id), 10)
		}
	} else {
		Fatalf("Need ID or label\n")
	}

	file := bpf.MapPath(policymap.MapName + lbl)
	fd, err := bpf.ObjGet(file)
	if err != nil {
		Fatalf("%s\n", err)
	}

	m := policymap.PolicyMap{Fd: fd}
	statsMap, err := m.DumpToSlice()
	if err != nil {
		Fatalf("Error while opening bpf Map: %s\n", err)
	}
	labelsID := map[policy.NumericIdentity]*policy.Identity{}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	const (
		labelsIDTitle  = "IDENTITY"
		labelsDesTitle = "LABELS (source:key[=value])"
		actionTitle    = "ACTION"
		bytesTitle     = "BYTES"
		packetsTitle   = "PACKETS"
	)

	for _, stat := range statsMap {
		if !printIDs {
			id := policy.NumericIdentity(stat.ID)
			if lbls, err := client.IdentityGet(id.StringID()); err != nil {
				fmt.Fprintf(os.Stderr, "Was impossible to retrieve label ID %d: %s\n",
					id, err)
			} else {
				labelsID[id] = policy.NewIdentityFromModel(lbls)
			}
		}

	}

	if printIDs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", labelsIDTitle, actionTitle, bytesTitle, packetsTitle)
	} else {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", labelsDesTitle, actionTitle, bytesTitle, packetsTitle)
	}
	for _, stat := range statsMap {
		id := policy.NumericIdentity(stat.ID)
		act := policy.ConsumableDecision(stat.Action)
		if printIDs {
			fmt.Fprintf(w, "%d\t%s\t%d\t%d\t\n", id, act.String(), stat.Bytes, stat.Packets)
		} else if lbls := labelsID[id]; lbls != nil {
			first := true
			for _, lbl := range lbls.Labels {
				if first {
					fmt.Fprintf(w, "%s\t%s\t%d\t%d\t\n", lbl, act.String(), stat.Bytes, stat.Packets)
					first = false
				} else {
					fmt.Fprintf(w, "%s\t\t\t\t\t\n", lbl)
				}
			}
		} else {
			fmt.Fprintf(w, "%d\t%s\t%d\t%d\t\n", id, act.String(), stat.Bytes, stat.Packets)
		}
	}
	w.Flush()
	if len(statsMap) == 0 {
		fmt.Printf("Policy stats empty. Perhaps the policy enforcement is disabled?\n")
	}
}

func updatePolicyKey(ctx *cli.Context, add bool) {
	if len(ctx.Args()) < 2 {
		Fatalf("Incorrect number of arguments.\n")
	}

	lbl := ctx.Args().Get(0)

	if lbl != "" {
		if id := policy.GetReservedID(lbl); id != policy.ID_UNKNOWN {
			lbl = "reserved_" + strconv.FormatUint(uint64(id), 10)
		}
	} else {
		Fatalf("Need ID or label\n")
	}

	file := bpf.MapPath(policymap.MapName + lbl)
	policyMap, _, err := policymap.OpenMap(file)
	if err != nil {
		Fatalf("Could not open policymap '%s' : %s", file, err)
	}

	peer_lbl, err := strconv.ParseUint(ctx.Args().Get(1), 10, 32)
	if add == true {
		err = policyMap.AllowConsumer(uint32(peer_lbl))
	} else {
		err = policyMap.DeleteConsumer(uint32(peer_lbl))
	}

	if err != nil {
		Fatalf("allow label %d failed for %s", peer_lbl, lbl)
	}
}

func addPolicyKey(ctx *cli.Context) {
	updatePolicyKey(ctx, true)
}

func removePolicyKey(ctx *cli.Context) {
	updatePolicyKey(ctx, false)
}

func dumpFirstEndpoint(w *tabwriter.Writer, ep *models.Endpoint, id string, label string) {
	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t\n",
		ep.ID, id, label, ep.Addressing.IPV6, ep.Addressing.IPV4, ep.State)
}

func dumpEndpoints(ctx *cli.Context) {
	eps, err := client.EndpointList()
	if err != nil {
		Fatalf("Error while getting endpoints from daemon: %s\n", err)
	}

	// FIXME: sorting
	//endpoint.OrderEndpointAsc(eps)

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	const (
		labelsIDTitle  = "IDENTITY"
		labelsDesTitle = "LABELS (source:key[=value])"
		ipv6Title      = "IPv6"
		ipv4Title      = "IPv4"
		endpointTitle  = "ID"
		statusTitle    = "STATUS"
	)

	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t\n",
		endpointTitle, labelsIDTitle, labelsDesTitle, ipv6Title, ipv4Title, statusTitle)

	for _, ep := range eps {
		if ep.Identity == nil {
			dumpFirstEndpoint(w, ep, "<no label id>", "")
		} else {
			id := fmt.Sprintf("%d", ep.Identity.ID)

			if len(ep.Identity.Labels) == 0 {
				dumpFirstEndpoint(w, ep, id, "no labels")
			} else {
				first := true
				for _, lbl := range ep.Identity.Labels {
					if first {
						dumpFirstEndpoint(w, ep, id, lbl)
						first = false
					} else {
						fmt.Fprintf(w, "\t\t%s\t\t\t\t\n", lbl)
					}
				}
			}
		}

	}
	w.Flush()
}

func recompileBPF(ctx *cli.Context) {
	_, id, err := endpoint.ValidateID(ctx.Args().First())
	if err != nil {
		Fatalf("%s", err)
	}

	if err := client.EndpointConfigPatch(id, nil); err != nil {
		Fatalf("Error while recompiling endpoint %s on daemon: %s\n", id, err)
	} else {
		fmt.Printf("Endpoint %s successfully recompiled\n", id)
	}
}

func detachBPF(ctx *cli.Context) {
	id := ctx.Args().First()
	if err := client.EndpointDelete(id); err != nil {
		fmt.Fprintf(os.Stderr, "Error while detaching endpoint %s on daemon: %s\n", id, err)
	} else {
		fmt.Printf("Endpoint %s's successfully detached\n", id)
	}
}

func listEndpointsBash(ctx *cli.Context) {
	eps, _ := client.EndpointList()
	if ctx.Args().Present() {
		if len(ctx.Args()) < 1 {
			firstArg := ctx.Args().First()
			for _, ep := range eps {
				if strings.HasPrefix(string(ep.ID), firstArg) {
					fmt.Println(ep.ID)
				}
			}
		}
	} else {
		for _, ep := range eps {
			fmt.Println(string(ep.ID))
		}
	}
}

func dumpCtProto(name string, ctType ctmap.CtType) {
	file := bpf.MapPath(name)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		Fatalf("Unable to open %s: %s\n", file, err)
	}

	m := ctmap.CtMap{Fd: fd, Type: ctType}
	out, err := m.Dump()
	if err != nil {
		Fatalf("Error while dumping BPF Map: %s\n", err)
	}

	fmt.Println(out)
}

func dumpCt(ctx *cli.Context) {
	lbl := ctx.Args().First()

	dumpCtProto(ctmap.MapName6+lbl, ctmap.CtTypeIPv6)
	dumpCtProto(ctmap.MapName4+lbl, ctmap.CtTypeIPv4)
}
