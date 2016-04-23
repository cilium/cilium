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

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/codegangsta/cli"
	l "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

var (
	CliCommand cli.Command
	client     *cnc.Client
	log        = l.MustGetLogger("cilium-tools-endpoint")
)

func init() {
	CliCommand = cli.Command{
		Name:    "endpoint",
		Aliases: []string{"e"},
		Usage:   "Manage endpoint operations",
		Before:  initEnv,
		Subcommands: []cli.Command{
			{
				Name:    "lxc-info",
				Aliases: []string{"l"},
				Usage:   "Dumps lxc-info of the given endpoint",
				Action:  dumpLXCInfo,
				Before:  verifyArguments,
			},
			{
				Name:      "bpf-map",
				Aliases:   []string{"b"},
				Usage:     "Dumps bpf policy-map of the given endpoint",
				Action:    dumpMap,
				ArgsUsage: "<endpoint>",
				Before:    verifyArguments,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "id, i",
						Usage: "Don't resolve label's ID",
					},
				},
			},
			{
				Name:    "policy",
				Aliases: []string{"p"},
				Usage:   "Manage policy status for the given endpoint",
				Subcommands: []cli.Command{
					{
						Name:      "enable",
						Aliases:   []string{"e"},
						Usage:     "Enables policy enforcement of the given endpoint",
						Before:    verifyArguments,
						ArgsUsage: "<endpoint>",
						Action:    enablePolicy,
					},
					{
						Name:      "disable",
						Aliases:   []string{"d"},
						Usage:     "Disables policy enforcement of the given endpoint",
						Before:    verifyArguments,
						ArgsUsage: "<endpoint>",
						Action:    disablePolicy,
					},
					{
						Name:      "status",
						Aliases:   []string{"s"},
						Usage:     "Returns the current policy status of the given endpoint",
						Before:    verifyArguments,
						ArgsUsage: "<endpoint>",
						Action:    getStatusPolicy,
					},
				},
			},
			{
				Name:    "nat46",
				Aliases: []string{"n"},
				Usage:   "Manage nat46 status for the given endpoint",
				Subcommands: []cli.Command{
					{
						Name:      "enable",
						Aliases:   []string{"e"},
						Usage:     "Enables NAT46 mode of the given endpoint",
						Before:    verifyArguments,
						ArgsUsage: "<endpoint>",
						Action:    enableNAT46,
					},
					{
						Name:      "disable",
						Aliases:   []string{"d"},
						Usage:     "Disables NAT46 mode of of the given endpoint",
						Before:    verifyArguments,
						ArgsUsage: "<endpoint>",
						Action:    disableNAT46,
					},
					{
						Name:      "status",
						Aliases:   []string{"s"},
						Usage:     "Returns the current NAT46 status of the given endpoint",
						Before:    verifyArguments,
						ArgsUsage: "<endpoint>",
						Action:    getStatusNAT46,
					},
				},
			},
		},
	}
}

func initEnv(ctx *cli.Context) error {
	if ctx.GlobalBool("debug") {
		common.SetupLOG(log, "DEBUG", "")
	} else {
		common.SetupLOG(log, "INFO", "")
	}
	return nil
}

func verifyArguments(ctx *cli.Context) error {
	ep := ctx.Args().First()
	if ep == "" {
		return fmt.Errorf("Error: empty endpoint")
	}
	return nil
}

func dumpLXCInfo(ctx *cli.Context) {
	epID := ctx.Args().First()

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return
	}

	client = c

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

	var c *cnc.Client
	if !printIDs {
		c, err = cnc.NewDefaultClient()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Was impossible to connect to cilium-daemon: %s\n"+
				"Proceding without resolving label's IDs", err)
			printIDs = true
		}
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
			secCtxLbl, err := c.GetLabels(int(stat.ID))
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

func enablePolicy(ctx *cli.Context) {
	epID := ctx.Args().First()

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return
	}

	err = c.EndpointUpdate(epID, types.EPOpts{common.DisablePolicyEnforcement: false})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with policy enforcement enabled\n", epID)
}

func disablePolicy(ctx *cli.Context) {
	epID := ctx.Args().First()

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return
	}

	err = c.EndpointUpdate(epID, types.EPOpts{common.DisablePolicyEnforcement: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with policy enforcement disabled\n", epID)
}

func getStatusPolicy(ctx *cli.Context) {
	epID := ctx.Args().First()

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return
	}

	ep, err := c.EndpointGet(epID)
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

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return
	}

	err = c.EndpointUpdate(epID, types.EPOpts{common.EnableNAT46: false})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with nat46 mode enabled\n", epID)
}

func disableNAT46(ctx *cli.Context) {
	epID := ctx.Args().First()

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return
	}

	err = c.EndpointUpdate(epID, types.EPOpts{common.EnableNAT46: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while updating endpoint %s on daemon: %s\n", epID, err)
		return
	}

	fmt.Printf("Endpoint %s with nat46 mode disabled\n", epID)
}

func getStatusNAT46(ctx *cli.Context) {
	epID := ctx.Args().First()

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return
	}

	ep, err := c.EndpointGet(epID)
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
