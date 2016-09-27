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
package endpoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/bpf/ctmap"
	"github.com/cilium/cilium/bpf/policymap"
	common "github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/bpf"
	cnc "github.com/cilium/cilium/common/client"
	"github.com/cilium/cilium/common/types"

	"github.com/codegangsta/cli"
	l "github.com/op/go-logging"
)

var (
	CliCommand cli.Command
	client     *cnc.Client
	log        = l.MustGetLogger("cilium-tools-endpoint")
)

func init() {
	CliCommand = cli.Command{
		Name:   "endpoint",
		Usage:  "Manage endpoint operations",
		Before: initEnv,
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
				Action:       dumpLXCInfo,
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

func initEnv(ctx *cli.Context) error {
	if ctx.GlobalBool("debug") {
		common.SetupLOG(log, "DEBUG")
	} else {
		common.SetupLOG(log, "INFO")
	}

	var (
		c   *cnc.Client
		err error
	)
	if host := ctx.GlobalString("host"); host == "" {
		c, err = cnc.NewDefaultClient()
	} else {
		c, err = cnc.NewClient(host, nil)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return fmt.Errorf("Error while creating cilium-client: %s", err)
	}
	client = c

	return nil
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

func getValidEPID(arg string) (uint16, error) {
	if arg == "" {
		return 0, fmt.Errorf("Empty endpoint")
	}
	epID, err := strconv.ParseUint(arg, 10, 16)
	return uint16(epID), err
}

func printEndpointLabels(lbls *types.OpLabels) {
	log.Debugf("All Labels %#v", *lbls)

	for _, lbl := range lbls.EndpointLabels {
		delete(lbls.UserLabels, lbl.Key)
		delete(lbls.ProbeLabels, lbl.Key)
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)

	for _, v := range lbls.EndpointLabels {
		text := common.Green("Enabled")

		fmt.Fprintf(w, "%s\t%s\n", v, text)
	}
	for _, v := range lbls.ProbeLabels {
		text := common.Red("Disabled")

		fmt.Fprintf(w, "%s\t%s\n", v, text)
	}
	for _, v := range lbls.UserLabels {
		text := common.Red("Disabled")

		fmt.Fprintf(w, "%s\t%s\n", v, text)
	}
	w.Flush()
}

func configLabels(ctx *cli.Context) {
	epID, err := getValidEPID(ctx.Args().First())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	addLabels := types.ParseStringLabels(ctx.StringSlice("add"))
	enableLabels := types.ParseStringLabels(ctx.StringSlice("enable"))
	disableLabels := types.ParseStringLabels(ctx.StringSlice("disable"))
	deleteLabels := types.ParseStringLabels(ctx.StringSlice("delete"))

	lo := types.LabelOp{}

	if len(addLabels) != 0 {
		lo[types.AddLabelsOp] = addLabels
	}
	if len(enableLabels) != 0 {
		lo[types.EnableLabelsOp] = enableLabels
	}
	if len(disableLabels) != 0 {
		lo[types.DisableLabelsOp] = disableLabels
	}
	if len(deleteLabels) != 0 {
		lo[types.DelLabelsOp] = deleteLabels
	}

	if err := client.EndpointLabelsUpdate(epID, lo); err != nil {
		log.Errorf("Error while deleting labels %s", err)
	}

	if lbls, err := client.EndpointLabelsGet(epID); err != nil {
		log.Errorf("Error while getting endpoint labels: %s", err)
	} else {
		if lbls != nil {
			printEndpointLabels(lbls)
		} else {
			fmt.Printf("(Endpoint with empty labels)")
		}
	}
}

func dumpLXCInfo(ctx *cli.Context) {
	epID, err := getValidEPID(ctx.Args().First())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	ep, err := client.EndpointGet(epID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting endpoint %d from daemon: %s\n", epID, err)
		return
	}
	if ep == nil {
		fmt.Printf("Endpoint %d not found\n", epID)
		return
	}

	fmt.Printf("Endpoint %d\n%s\n", ep.ID, ep)
	fmt.Printf("Endpoint status: \n%s\n", ep.Status.DumpLog())
}

func listEndpointOptions() {
	for k, s := range types.EndpointOptionLibrary {
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
	epID, err := getValidEPID(ctx.Args().First())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	ep, err := client.EndpointGet(epID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting endpoint %d from daemon: %s\n", epID, err)
		os.Exit(1)
	}

	if ep == nil {
		fmt.Printf("Endpoint %d not found\n", epID)
		os.Exit(1)
	}

	opts := ctx.Args().Tail()
	if len(opts) == 0 {
		ep.Opts.Dump()
		return
	}

	epOpts := make(types.OptionMap, len(opts))

	for k := range opts {
		name, value, err := types.ParseOption(opts[k], &types.EndpointOptionLibrary)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		epOpts[name] = value
	}

	err = client.EndpointUpdate(ep.ID, epOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to update endpoint %d: %s\n", ep.ID, err)
		os.Exit(1)
	}
}

func dumpMap(ctx *cli.Context) {
	lbl := ctx.Args().First()
	printIDs := ctx.Bool("id")

	if lbl != "" {
		if id := types.GetID(lbl); id != types.ID_UNKNOWN {
			lbl = "reserved_" + strconv.FormatUint(uint64(id), 10)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Need ID or label\n")
		return
	}

	file := common.PolicyMapPath + lbl
	fd, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	m := policymap.PolicyMap{Fd: fd}
	statsMap, err := m.DumpToSlice()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while opening bpf Map: %s\n", err)
		return
	}
	labelsID := map[uint32]*types.SecCtxLabel{}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	const (
		labelsIDTitle  = "LABEL ID"
		labelsDesTitle = "LABELS (source:key[=value])"
		actionTitle    = "ACTION"
		bytesTitle     = "BYTES"
		packetsTitle   = "PACKETS"
	)

	for _, stat := range statsMap {
		if !printIDs {
			secCtxLbl, err := client.GetLabels(stat.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Was impossible to retrieve label ID %d: %s\n",
					stat.ID, err)
			}
			if secCtxLbl == nil {
				fmt.Fprintf(os.Stderr, "Label with ID %d was not found\n",
					stat.ID)
			}
			labelsID[stat.ID] = secCtxLbl
		}

	}

	if printIDs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", labelsIDTitle, actionTitle, bytesTitle, packetsTitle)
	} else {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", labelsDesTitle, actionTitle, bytesTitle, packetsTitle)
	}
	for _, stat := range statsMap {
		act := types.ConsumableDecision(stat.Action)
		if printIDs {
			fmt.Fprintf(w, "%d\t%s\t%d\t%d\t\n", stat.ID, act.String(), stat.Bytes, stat.Packets)
		} else if lbls := labelsID[stat.ID]; lbls != nil {
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
			fmt.Fprintf(w, "%d\t%s\t%d\t%d\t\n", stat.ID, act.String(), stat.Bytes, stat.Packets)
		}
	}
	w.Flush()
	if len(statsMap) == 0 {
		fmt.Printf("Policy stats empty. Perhaps the policy enforcement is disabled?\n")
	}
}

func updatePolicyKey(ctx *cli.Context, add bool) {
	if len(ctx.Args()) < 2 {
		fmt.Fprintf(os.Stderr, "Incorrect number of arguments.\n")
		return
	}

	lbl := ctx.Args().Get(0)

	if lbl != "" {
		if id := types.GetID(lbl); id != types.ID_UNKNOWN {
			lbl = "reserved_" + strconv.FormatUint(uint64(id), 10)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Need ID or label\n")
		return
	}

	file := common.PolicyMapPath + lbl
	policyMap, _, err := policymap.OpenMap(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open policymap '%s' : %s", file, err)
		return
	}

	peer_lbl, err := strconv.ParseUint(ctx.Args().Get(1), 10, 32)
	if add == true {
		err = policyMap.AllowConsumer(uint32(peer_lbl))
	} else {
		err = policyMap.DeleteConsumer(uint32(peer_lbl))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "allow label %d failed for %s", peer_lbl, lbl)
		return
	}
}

func addPolicyKey(ctx *cli.Context) {
	updatePolicyKey(ctx, true)
}

func removePolicyKey(ctx *cli.Context) {
	updatePolicyKey(ctx, false)
}

func dumpFirstEndpoint(w *tabwriter.Writer, ep *types.Endpoint, seclabel string, label string) {
	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t\n", ep.ID, seclabel, label, ep.IPv6.String(), ep.IPv4.String(), ep.Status.String())
}

func dumpEndpoints(ctx *cli.Context) {
	eps, err := client.EndpointsGet()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting endpoints from daemon: %s\n", err)
		return
	}
	if eps == nil {
		fmt.Printf("No endpoints\n")
		return
	}

	types.OrderEndpointAsc(eps)

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	const (
		labelsIDTitle  = "LABEL ID"
		labelsDesTitle = "LABELS (source:key[=value])"
		ipv6Title      = "IPv6"
		ipv4Title      = "IPv4"
		endpointTitle  = "ENDPOINT ID"
		statusTitle    = "STATUS"
	)

	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t\n",
		endpointTitle, labelsIDTitle, labelsDesTitle, ipv6Title, ipv4Title, statusTitle)

	for _, ep := range eps {
		if ep.SecLabel == nil {
			dumpFirstEndpoint(w, &ep, "<no label id>", "")
		} else {
			seclabel := fmt.Sprintf("%d", ep.SecLabel.ID)

			if len(ep.SecLabel.Labels) == 0 {
				dumpFirstEndpoint(w, &ep, seclabel, "no labels")
			} else {
				first := true
				for _, lbl := range ep.SecLabel.Labels {
					if first {
						dumpFirstEndpoint(w, &ep, seclabel, lbl.String())
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
	epID, err := getValidEPID(ctx.Args().First())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	err = client.EndpointUpdate(epID, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while recompiling endpoint %d on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %d's successfully recompiled\n", epID)
}

func detachBPF(ctx *cli.Context) {
	epID, err := getValidEPID(ctx.Args().First())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	err = client.EndpointLeave(epID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while detaching endpoint %d on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %d's successfully detached\n", epID)
}

func listEndpointsBash(ctx *cli.Context) {
	eps, _ := client.EndpointsGet()
	if ctx.Args().Present() {
		if len(ctx.Args()) < 1 {
			firstArg := ctx.Args().First()
			for _, ep := range eps {
				if strings.HasPrefix(strconv.Itoa(int(ep.ID)), firstArg) {
					fmt.Println(ep.ID)
				}
			}
		}
	} else {
		for _, ep := range eps {
			fmt.Println(ep.ID)
		}
	}

}

func dumpCtProto(file string, ctType ctmap.CtType) {
	fd, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open %s: %s\n", file, err)
		os.Exit(1)
	}

	m := ctmap.CtMap{Fd: fd, Type: ctType}
	out, err := m.Dump()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while dumping BPF Map: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(out)
}

func dumpCt(ctx *cli.Context) {
	lbl := ctx.Args().First()

	dumpCtProto(common.BPFMapCT6+lbl, ctmap.CtTypeIPv6)
	dumpCtProto(common.BPFMapCT4+lbl, ctmap.CtTypeIPv4)
}
