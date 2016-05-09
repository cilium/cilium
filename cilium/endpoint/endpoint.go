package endpoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/noironetworks/cilium-net/bpf/policymap"
	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/bpf"
	cnc "github.com/noironetworks/cilium-net/common/client"
	"github.com/noironetworks/cilium-net/common/types"

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
				Name:   "list",
				Usage:  "Dumps a list of all daemon's endpoints",
				Action: dumpEndpoints,
			},
			{
				Name:  "nat46",
				Usage: "Manage nat46 status for the given endpoint",
				Subcommands: []cli.Command{
					{
						Name:         "enable",
						Usage:        "Enables NAT46 mode of the given endpoint",
						Before:       verifyArguments,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint>",
						Action:       enableNAT46,
					},
					{
						Name:         "disable",
						Usage:        "Disables NAT46 mode of of the given endpoint",
						Before:       verifyArguments,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint>",
						Action:       disableNAT46,
					},
					{
						Name:         "status",
						Usage:        "Returns the current NAT46 status of the given endpoint",
						Before:       verifyArguments,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint>",
						Action:       getStatusNAT46,
					},
				},
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
					{
						Name:         "enable",
						Usage:        "Enables policy enforcement of the given endpoint",
						Before:       verifyArguments,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint>",
						Action:       enablePolicy,
					},
					{
						Name:         "disable",
						Usage:        "Disables policy enforcement of the given endpoint",
						Before:       verifyArguments,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint>",
						Action:       disablePolicy,
					},
					{
						Name:         "status",
						Usage:        "Returns the current policy status of the given endpoint",
						Before:       verifyArguments,
						BashComplete: listEndpointsBash,
						ArgsUsage:    "<endpoint>",
						Action:       getStatusPolicy,
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
			{
				Name:  "drop-notify",
				Usage: "Manage drop notification status for the given endpoint",
				Subcommands: []cli.Command{
					{
						Name:      "enable",
						Aliases:   []string{"e"},
						Usage:     "Enables Drop Notification mode of the given endpoint",
						Before:    verifyArguments,
						ArgsUsage: "<endpoint>",
						Action:    enableDropNotify,
					},
					{
						Name:      "disable",
						Aliases:   []string{"d"},
						Usage:     "Disables Drop Notification mode of of the given endpoint",
						Before:    verifyArguments,
						ArgsUsage: "<endpoint>",
						Action:    disableDropNotify,
					},
					{
						Name:      "status",
						Aliases:   []string{"s"},
						Usage:     "Returns the current Drop Notification status of the given endpoint",
						Before:    verifyArguments,
						ArgsUsage: "<endpoint>",
						Action:    getStatusDropNotify,
					},
				},
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
		c, err = cnc.NewClient(host, nil, nil, nil)
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

func dumpLXCInfo(ctx *cli.Context) {
	epID := ctx.Args().First()

	ep, err := client.EndpointGet(epID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting endpoint %s from daemon: %s\n", epID, err)
		return
	}
	if ep == nil {
		fmt.Printf("Endpoint %s not found\n", epID)
		return
	}

	fmt.Printf("Endpoint %s\n%s\n", ep.ID, ep)
}

func setIfGT(dst *int, src int) {
	if src > *dst {
		*dst = src
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
		labelsDesTitle = "LABELS (Source#Key[=Value])"
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
					fmt.Fprintf(w, "\t\t%s\t\t\t\n", lbl)
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
	policyMap, err := policymap.OpenMap(file)
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

func enablePolicy(ctx *cli.Context) {
	epID := ctx.Args().First()

	err := client.EndpointUpdate(epID, types.EPOpts{common.DisablePolicyEnforcement: false})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with policy enforcement enabled\n", epID)
}

func disablePolicy(ctx *cli.Context) {
	epID := ctx.Args().First()

	err := client.EndpointUpdate(epID, types.EPOpts{common.DisablePolicyEnforcement: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with policy enforcement disabled\n", epID)
}

func getStatusPolicy(ctx *cli.Context) {
	epID := ctx.Args().First()

	ep, err := client.EndpointGet(epID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting endpoint %s from daemon: %s\n", epID, err)
		return
	}
	if ep == nil {
		fmt.Printf("Endpoint %s not found\n", epID)
		return
	}

	if v, ok := ep.Opts[common.DisablePolicyEnforcement]; ok {
		fmt.Printf("Endpoint %s with %s set %t\n",
			ep.ID, common.DisablePolicyEnforcement, v)
		return
	}
	fmt.Printf("Endpoint %s with %s set %t\n",
		ep.ID, common.DisablePolicyEnforcement, false)
}

func enableNAT46(ctx *cli.Context) {
	epID := ctx.Args().First()

	err := client.EndpointUpdate(epID, types.EPOpts{common.EnableNAT46: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with nat46 mode enabled\n", epID)
}

func disableNAT46(ctx *cli.Context) {
	epID := ctx.Args().First()

	err := client.EndpointUpdate(epID, types.EPOpts{common.EnableNAT46: false})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with nat46 mode disabled\n", epID)
}

func getStatusNAT46(ctx *cli.Context) {
	epID := ctx.Args().First()

	ep, err := client.EndpointGet(epID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting endpoint %s from daemon: %s\n", epID, err)
		return
	}
	if ep == nil {
		fmt.Printf("Endpoint %s not found\n", epID)
		return
	}

	if v, ok := ep.Opts[common.EnableNAT46]; ok {
		fmt.Printf("Endpoint %s with %s set %t\n", ep.ID, common.EnableNAT46, v)
		return
	}
	fmt.Printf("Endpoint %s with %s set %t\n", ep.ID, common.EnableNAT46, false)
}

func enableDropNotify(ctx *cli.Context) {
	epID := ctx.Args().First()

	err := client.EndpointUpdate(epID, types.EPOpts{common.EnableDropNotify: false})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with drop notification mode enabled\n", epID)
}

func disableDropNotify(ctx *cli.Context) {
	epID := ctx.Args().First()

	err := client.EndpointUpdate(epID, types.EPOpts{common.EnableDropNotify: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with drop notification mode disabled\n", epID)
}

func getStatusDropNotify(ctx *cli.Context) {
	epID := ctx.Args().First()

	ep, err := client.EndpointGet(epID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting endpoint %s from daemon: %s\n", epID, err)
		return
	}
	if ep == nil {
		fmt.Printf("Endpoint %s not found\n", epID)
		return
	}

	if v, ok := ep.Opts[common.EnableDropNotify]; ok {
		fmt.Printf("Endpoint %s with %s set %t\n", ep.ID, common.EnableDropNotify, v)
		return
	}
	fmt.Printf("Endpoint %s with %s set %t\n", ep.ID, common.EnableDropNotify, false)
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
		labelsDesTitle = "LABELS (Source#Key[=Value])"
		ipv6Title      = "IPv6"
		endpointTitle  = "ENDPOINT ID"
	)

	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", endpointTitle, labelsIDTitle, labelsDesTitle, ipv6Title)

	for _, ep := range eps {
		if ep.SecLabel != nil {
			if len(ep.SecLabel.Labels) != 0 {
				first := true
				for _, lbl := range ep.SecLabel.Labels {
					if first {
						fmt.Fprintf(w, "%s\t%d\t%s\t%s\t\n", ep.ID, ep.SecLabel.ID, lbl, ep.LXCIP.String())
						first = false
					} else {
						fmt.Fprintf(w, "\t\t%s\t\t\n", lbl)
					}
				}
			} else {
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\t\n", ep.ID, ep.SecLabel.ID, "(no labels)", ep.LXCIP.String())
			}
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", ep.ID, "(empty sec label ID)", "", ep.LXCIP.String())
		}
	}
	w.Flush()
}

func recompileBPF(ctx *cli.Context) {
	epID := ctx.Args().First()

	err := client.EndpointUpdate(epID, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while recompiling endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s's successfully recompiled\n", epID)
}

func detachBPF(ctx *cli.Context) {
	epID := ctx.Args().First()

	err := client.EndpointLeave(epID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while detaching endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s's successfully detached\n", epID)
}

func listEndpointsBash(ctx *cli.Context) {
	eps, _ := client.EndpointsGet()
	if ctx.Args().Present() {
		if len(ctx.Args()) < 1 {
			firstArg := ctx.Args().First()
			for _, ep := range eps {
				if strings.HasPrefix(ep.ID, firstArg) {
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
