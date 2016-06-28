package endpoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/noironetworks/cilium-net/bpf/ctmap"
	"github.com/noironetworks/cilium-net/bpf/policymap"
	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/bpf"
	cnc "github.com/noironetworks/cilium-net/common/client"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/codegangsta/cli"
	"github.com/fatih/color"
	l "github.com/op/go-logging"
)

var (
	CliCommand cli.Command
	client     *cnc.Client
	log        = l.MustGetLogger("cilium-tools-endpoint")
	green      = color.New(color.FgGreen).SprintFunc()
	red        = color.New(color.FgRed).SprintFunc()
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

func listEndpointOptions() {
	for k, s := range types.EndpointOptionLibrary {
		fmt.Printf("%-24s %s\n", k, s.Description)
	}
}

func printEndpointConfig(ep *types.Endpoint) {
	for k, _ := range ep.Opts {
		text := green("Enabled")

		if !ep.Opts[k] {
			text = red("Disabled")
		}

		fmt.Printf("%-24s %s\n", k, text)
	}
}

func parseEPOpt(arg string) (string, bool, error) {
	enabled := true

	if arg[0] == '!' {
		enabled = false
		arg = arg[1:]
	}

	optionSplit := strings.SplitN(arg, "=", 2)
	arg = optionSplit[0]
	if len(optionSplit) > 1 {
		switch strings.ToLower(optionSplit[1]) {
		case "true", "on", "enable", "enabled":
			enabled = true
		case "false", "off", "disable", "disabled":
			enabled = false
		default:
			return "", false, fmt.Errorf("Invalid option value %s", optionSplit[1])
		}
	}

	key, spec := types.LookupEndpointOption(arg)
	if key == "" {
		return "", false, fmt.Errorf("Unknown endpoint option %s", arg)
	}

	if spec.Immutable {
		return "", false, fmt.Errorf("Specified option is immutable (read-only)")
	}

	return key, enabled, nil
}

func verifyConfigEndpoint(ctx *cli.Context) error {
	if ctx.Args().First() == "" {
		return fmt.Errorf("Error: Need endpoint ID")
	}
	return nil
}

func configEndpoint(ctx *cli.Context) {
	epID := ctx.Args().First()

	if epID == "list" {
		listEndpointOptions()
		return
	}

	ep, err := client.EndpointGet(epID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting endpoint %s from daemon: %s\n", epID, err)
		os.Exit(1)
	}

	if ep == nil {
		fmt.Printf("Endpoint %s not found\n", epID)
		os.Exit(1)
	}

	opts := ctx.Args().Tail()
	if len(opts) == 0 {
		printEndpointConfig(ep)
		return
	}

	epOpts := make(types.EPOpts, len(opts))

	for k, _ := range opts {
		name, value, err := parseEPOpt(opts[k])
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		epOpts[name] = value
	}

	err = client.EndpointUpdate(ep.ID, epOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to update endpoint %s: %s\n", ep.ID, err)
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

func dumpCt(ctx *cli.Context) {
	lbl := ctx.Args().First()

	file := common.BPFMapCT + lbl
	fd, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open %s: %s\n", file, err)
		os.Exit(1)
	}

	m := ctmap.CtMap{Fd: fd}
	out, err := m.Dump()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while opening bpf Map: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(out)
}
