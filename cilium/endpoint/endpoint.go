package endpoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "id, i",
						Usage: "Don't resolve label's ID",
					},
				},
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
			lbl = "reserved_" + strconv.Itoa(int(id))
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

	var (
		maxIDSize                   = len("Label's ID")
		maxActionSize               = len("Action")
		maxBytesSize                = len("Bytes")
		maxPacketsSize              = len("Packets")
		labelsID                    = map[uint32]*types.SecCtxLabel{}
		dataString, dataLabelString string
	)
	if !printIDs {
		maxIDSize = len("Labels (Source#Key[=Value])")
	}
	for _, stat := range statsMap {
		act := types.ConsumableDecision(stat.Action)
		setIfGT(&maxActionSize, len(act.String()))
		setIfGT(&maxBytesSize, len(strconv.FormatUint(stat.Bytes, 10)))
		setIfGT(&maxPacketsSize, len(strconv.FormatUint(stat.Packets, 10)))

		if printIDs {
			setIfGT(&maxIDSize, len(strconv.FormatUint(uint64(stat.ID), 10)))
		} else {
			secCtxLbl, err := client.GetLabels(int(stat.ID))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Was impossible to retrieve label ID %d: %s\n",
					stat.ID, err)
			}
			if secCtxLbl == nil {
				fmt.Fprintf(os.Stderr, "Label with ID %d was not found\n",
					stat.ID)
			}
			labelsID[stat.ID] = secCtxLbl
			if secCtxLbl != nil {
				for _, lbl := range secCtxLbl.Labels {
					setIfGT(&maxIDSize, len(lbl.String()))
				}
			}
		}

	}
	columnWidth := 3
	maxIDSize += columnWidth
	maxActionSize += columnWidth
	maxBytesSize += columnWidth
	maxPacketsSize += columnWidth

	if printIDs {
		titleString := fmt.Sprintf("%%%ds%%%ds%%%ds%%%ds\n",
			maxIDSize, maxActionSize, maxBytesSize, maxPacketsSize)

		dataString = fmt.Sprintf("%%%dd%%%ds%%%dd%%%dd\n",
			maxIDSize, maxActionSize, maxBytesSize, maxPacketsSize)

		fmt.Printf(titleString, "Label's ID", "Action", "Bytes", "Packets")
	} else {
		titleString := fmt.Sprintf("   %%-%ds%%%ds%%%ds%%%ds\n",
			maxIDSize-columnWidth, maxActionSize, maxBytesSize, maxPacketsSize)

		dataString = fmt.Sprintf("   %%-%ds%%%ds%%%dd%%%dd\n",
			maxIDSize-columnWidth, maxActionSize, maxBytesSize, maxPacketsSize)

		dataLabelString = fmt.Sprintf("   %%-%ds\n", maxIDSize-columnWidth)

		fmt.Printf(titleString, "Labels (Source#Key[=Value])", "Action", "Bytes", "Packets")
	}

	fmt.Printf("%s\n", strings.Repeat("-", maxIDSize+maxActionSize+maxBytesSize+maxPacketsSize))

	for _, stat := range statsMap {
		act := types.ConsumableDecision(stat.Action)
		if printIDs {
			fmt.Printf(dataString, stat.ID, act, stat.Bytes, stat.Packets)
		} else if lbls := labelsID[stat.ID]; lbls != nil {
			first := true
			for _, lbl := range lbls.Labels {
				if len(lbls.Labels) == 1 {
					fmt.Printf(dataString, lbl, act, stat.Bytes, stat.Packets)
				} else if first {
					fmt.Printf(dataLabelString, lbl)
					first = false
				} else {
					fmt.Printf(dataString, lbl, act, stat.Bytes, stat.Packets)
				}
			}
		} else {
			fmt.Printf(dataString, stat.ID, act.String(), stat.Bytes, stat.Packets)
		}
		fmt.Printf("%s\n", strings.Repeat("-", maxIDSize+maxActionSize+maxBytesSize+maxPacketsSize))
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
			lbl = "reserved_" + strconv.Itoa(int(id))
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

	err := client.EndpointUpdate(epID, types.EPOpts{common.EnableNAT46: false})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with nat46 mode enabled\n", epID)
}

func disableNAT46(ctx *cli.Context) {
	epID := ctx.Args().First()

	err := client.EndpointUpdate(epID, types.EPOpts{common.EnableNAT46: true})
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
	printIDs := ctx.Bool("id")

	eps, err := client.EndpointsGet()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while getting endpoints from daemon: %s\n", err)
		return
	}
	if eps == nil {
		fmt.Printf("No endpoints\n")
		return
	}

	var (
		maxIDSize                                 = len("Label's ID")
		maxEpIDSize                               = len("Endpoint ID")
		labelsID                                  = map[uint32]*types.SecCtxLabel{}
		dataIDString, dataString, dataLabelString string
	)

	if !printIDs {
		maxIDSize = len("Labels (Source#Key[=Value])")
	}

	for _, ep := range eps {
		setIfGT(&maxEpIDSize, len(ep.ID))

		if printIDs {
			setIfGT(&maxIDSize, len(strconv.FormatUint(uint64(ep.SecLabelID), 10)))
		} else {
			secCtxLbl, err := client.GetLabels(int(ep.SecLabelID))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Was impossible to retrieve label ID %d: %s\n",
					ep.SecLabelID, err)
			}
			if secCtxLbl == nil {
				fmt.Fprintf(os.Stderr, "Label with ID %d was not found\n",
					ep.SecLabelID)
			}
			labelsID[ep.SecLabelID] = secCtxLbl
			if secCtxLbl != nil {
				for _, lbl := range secCtxLbl.Labels {
					setIfGT(&maxIDSize, len(lbl.String()))
				}
			}
		}

	}
	columnWidth := 3
	maxEpIDSize += columnWidth
	maxIDSize += columnWidth

	titleString := fmt.Sprintf("%%-%ds%%%ds\n", maxEpIDSize, maxIDSize)
	dataIDString = fmt.Sprintf("%%-%ds%%%dd\n", maxEpIDSize, maxIDSize)
	if printIDs {
		fmt.Printf(titleString, "Endpoint ID", "Label's ID")
	} else {
		dataString = fmt.Sprintf("%%-%ds%%%ds\n", maxEpIDSize, maxIDSize)

		dataLabelString = fmt.Sprintf("%%%ds\n", maxEpIDSize+maxIDSize)

		fmt.Printf(titleString, "Endpoint ID", "Labels (Source#Key[=Value])")
	}

	fmt.Printf("%s\n", strings.Repeat("-", maxEpIDSize+maxIDSize))

	for _, ep := range eps {
		if printIDs {
			fmt.Printf(dataIDString, ep.ID, ep.SecLabelID)
		} else if lbls := labelsID[ep.SecLabelID]; lbls != nil && len(lbls.Labels) != 0 {
			first := true
			for _, lbl := range lbls.Labels {
				if len(lbls.Labels) == 1 {
					fmt.Printf(dataString, ep.ID, lbl)
				} else if first {
					fmt.Printf(dataString, ep.ID, lbl)
					first = false
				} else {
					fmt.Printf(dataLabelString, lbl)
				}
			}
		} else {
			fmt.Printf(dataIDString, ep.ID, ep.SecLabelID)
		}
		fmt.Printf("%s\n", strings.Repeat("-", maxEpIDSize+maxIDSize))
	}

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
