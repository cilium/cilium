package policy_repo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/noironetworks/cilium-net/common"
	cnc "github.com/noironetworks/cilium-net/common/client"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/codegangsta/cli"
	l "github.com/op/go-logging"
)

var (
	client             *cnc.Client
	ignoredMasksSource = []string{".git"}
	ignoredMasks       []*regexp.Regexp
	log                = l.MustGetLogger("cilium-net-policy-repo")
	CliCommand         cli.Command
)

func init() {
	ignoredMasks = make([]*regexp.Regexp, len(ignoredMasksSource))

	for i, _ := range ignoredMasksSource {
		ignoredMasks[i] = regexp.MustCompile(ignoredMasksSource[i])
	}
}

func initEnv(ctx *cli.Context) error {
	if ctx.GlobalBool("debug") {
		common.SetupLOG(log, "DEBUG", "")
	} else {
		common.SetupLOG(log, "INFO", "")
	}

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return fmt.Errorf("Error while creating cilium-client: %s", err)
	}

	client = c

	return nil
}

func verifyArgumentsValidate(ctx *cli.Context) error {
	path := ctx.Args().First()
	if path == "" {
		return fmt.Errorf("Error: empty path")
	}
	return initEnv(ctx)
}

func verifyAllowedSlice(slice []string) error {
	for i, v := range slice {
		if _, err := strconv.ParseUint(v, 10, 32); err != nil {
			// can fail which means it needs to be a label
			_, err := types.ParseLabel(v)
			if err != nil {
				return fmt.Errorf("value %q: must be only one unsigned "+
					"number or label(s) in format of SOURCE#KEY[=VALUE]", v)
			}
		} else if i != 0 {
			return fmt.Errorf("value %q: must be only one unsigned "+
				"number or label(s) in format of SOURCE#KEY[=VALUE]", v)
		}
	}
	return nil
}

func verifyArgumentsPolicy(ctx *cli.Context) error {
	srcSlice := ctx.StringSlice("source")
	if len(srcSlice) == 0 {
		return fmt.Errorf("Empty source")
	}

	dstSlice := ctx.StringSlice("destination")
	if len(srcSlice) == 0 {
		return fmt.Errorf("Empty destination")
	}

	if err := verifyAllowedSlice(srcSlice); err != nil {
		return fmt.Errorf("Invalid source: %s", err)
	}

	if err := verifyAllowedSlice(dstSlice); err != nil {
		return fmt.Errorf("Invalid destination: %s", err)
	}

	return initEnv(ctx)
}

func init() {
	CliCommand = cli.Command{
		Name:  "policy",
		Usage: "Manage policy operations",
		Subcommands: []cli.Command{
			{
				Name:      "validate",
				Aliases:   []string{"v"},
				Usage:     "Validate a policy (sub)tree",
				Action:    validatePolicy,
				ArgsUsage: "<path>",
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "dump, d",
						Usage: "Dump parsed policy tree after validation",
					},
				},
				Before: verifyArgumentsValidate,
			},
			{
				Name:      "import",
				Aliases:   []string{"i"},
				Usage:     "Import a policy (sub)tree",
				Action:    importPolicy,
				ArgsUsage: "<path>",
				Before:    verifyArgumentsValidate,
			},
			{
				Name:      "dump",
				Usage:     "Dump policy (sub)tree",
				Action:    dumpPolicy,
				ArgsUsage: "<path>",
				Before:    verifyArgumentsValidate,
			},
			{
				Name:      "delete",
				Usage:     "Delete policy (sub)tree",
				Action:    deletePolicy,
				ArgsUsage: "<path>",
				Before:    verifyArgumentsValidate,
			},
			{
				Name:   "get-id",
				Usage:  "Lookup security context id",
				Action: getSecID,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "list, l",
						Usage: "List all reserved IDs",
					},
				},
				Before: initEnv,
			},
			{
				Name: "allowed",
				Usage: "Verifies if source ID or LABEL(s) is allowed to consume destination ID or LABEL(s). " +
					"LABEL is represented as SOURCE#KEY[=VALUE]",
				Action: verifyPolicy,
				Flags: []cli.Flag{
					cli.StringSliceFlag{
						Name: "source, s",
					},
					cli.StringSliceFlag{
						Name: "destination, d",
					},
				},
				Before: verifyArgumentsPolicy,
			},
		},
	}
}

func getContext(content []byte, offset int64) (int, string, int) {
	if offset >= int64(len(content)) || offset < 0 {
		return 0, fmt.Sprintf("[error: Offset %d is out of bounds 0..%d]", offset, len(content)), 0
	}

	lineN := strings.Count(string(content[:offset]), "\n") + 1

	start := strings.LastIndexByte(string(content[:offset]), '\n')
	if start == -1 {
		start = 0
	} else {
		start++
	}

	end := strings.IndexByte(string(content[start:]), '\n')
	l := ""
	if end == -1 {
		l = string(content[start:])
	} else {
		end = end + start
		l = string(content[start:end])
	}

	return lineN, l, (int(offset) - start)
}

func handleUnmarshalError(f string, content []byte, err error) error {
	switch e := err.(type) {
	case *json.SyntaxError:
		line, ctx, off := getContext(content, e.Offset)
		return fmt.Errorf("Error: %s:%d: Syntax error at offset %d:\n%s\n%*c",
			path.Base(f), line, off, ctx, off, '^')
	case *json.UnmarshalTypeError:
		line, ctx, off := getContext(content, e.Offset)
		return fmt.Errorf("Error: %s:%d: Unable to assign value '%s' to type '%v':\n%s\n%*c",
			path.Base(f), line, e.Value, e.Type, ctx, off, '^')
	default:
		return fmt.Errorf("Error: %s: Unknown error:%s", path.Base(f), err)
	}
}

func loadPolicyFile(path string) (*types.PolicyNode, error) {
	log.Debugf("Loading file %s", path)

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var policyNode types.PolicyNode
	err = json.Unmarshal(content, &policyNode)
	if err != nil {
		return nil, handleUnmarshalError(path, content, err)
	}

	return &policyNode, nil
}

func ignoredFile(name string) bool {
	for i := range ignoredMasks {
		if ignoredMasks[i].MatchString(name) {
			log.Debugf("Ignoring file %s", name)
			return true
		}
	}

	return false
}

func loadPolicyDirectory(name string) (*types.PolicyNode, error) {
	log.Debugf("Entering directory %s...", name)

	files, err := ioutil.ReadDir(name)
	if err != nil {
		return nil, err
	}

	var node *types.PolicyNode

	// process all files first
	for _, f := range files {
		if f.IsDir() || ignoredFile(path.Base(f.Name())) {
			continue
		}

		if p, err := loadPolicyFile(name + "/" + f.Name()); err != nil {
			return nil, err
		} else {
			if node != nil {
				if err := node.Merge(p); err != nil {
					return nil, fmt.Errorf("Error: %s: %s", f.Name(), err)
				}
			} else {
				node = p
			}
		}
	}

	// recursive search
	for _, f := range files {
		if f.IsDir() {
			if ignoredFile(path.Base(f.Name())) {
				continue
			}
			subpath := name + "/" + f.Name()
			if p, err := loadPolicyDirectory(subpath); err != nil {
				return nil, err
			} else {
				if p.Name == "" {
					return nil, fmt.Errorf("Policy node import from %s did not derive a name",
						subpath)
				}

				node.AddChild(p.Name, p)
			}
		}
	}

	log.Debugf("Leaving directory %s...", name)

	return node, nil
}

func importPolicy(ctx *cli.Context) {
	path := ctx.Args().First()
	if node, err := loadPolicyDirectory(path); err != nil {
		fmt.Fprintf(os.Stderr, "Could not import policy directory %s: %s\n", path, err)
		os.Exit(1)
	} else {
		log.Debugf("Constructed policy object for import %+v", node)

		// Ignore request if no policies have been found
		if node == nil {
			return
		}

		if err := client.PolicyAdd(node.Name, node); err != nil {
			fmt.Fprintf(os.Stderr, "Could not import policy directory %s: %s\n", path, err)
			os.Exit(1)
		}
	}
}

func prettyPrint(node *types.PolicyNode) {
	if b, err := json.MarshalIndent(node, "", "  "); err != nil {
		fmt.Fprintf(os.Stderr, "Could not marshal response: %s\n", err)
	} else {
		fmt.Printf("%s\n", b)
	}
}

func validatePolicy(ctx *cli.Context) {
	path := ctx.Args().First()
	if node, err := loadPolicyDirectory(path); err != nil {
		fmt.Fprintf(os.Stderr, "Validation of %s failed\n%s\n", path, err)
		os.Exit(1)
	} else {
		fmt.Printf("All policy elements are valid.\n")

		if ctx.Bool("dump") {
			fmt.Printf("%s\n", node.DebugString(1))
			prettyPrint(node)
		}
	}
}

func dumpPolicy(ctx *cli.Context) {
	path := ctx.Args().First()

	n, err := client.PolicyGet(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not retrieve policy for: %s: %s\n", path, err)
		os.Exit(1)
	}

	prettyPrint(n)
}

func deletePolicy(ctx *cli.Context) {
	path := ctx.Args().First()

	if err := client.PolicyDelete(path); err != nil {
		fmt.Fprintf(os.Stderr, "Could not retrieve policy for: %s: %s\n", path, err)
		os.Exit(1)
	}
}

func getSecID(ctx *cli.Context) {
	if ctx.Bool("list") {
		for k, v := range types.ResDec {
			fmt.Printf("%-15s %3d\n", k, v)
		}
		return
	}

	lbl := ctx.Args().First()

	if id := types.GetID(lbl); id != types.ID_UNKNOWN {
		fmt.Printf("%d\n", id)
	} else {
		os.Exit(1)
	}
}

func parseAllowedSlice(slice []string) ([]types.Label, error) {
	inLabels := []types.Label{}
	var (
		id          uint64
		err         error
		secCtxLabel *types.SecCtxLabel
	)
	for _, v := range slice {
		if id, err = strconv.ParseUint(v, 10, 32); err != nil {
			// can fail which means it needs to be a label
			lbl, err := types.ParseLabel(v)
			if err != nil {
				return nil, fmt.Errorf("value %q: must be a unsigned "+
					"number or label in format of SOURCE#KEY[=VALUE]", v)
			}
			inLabels = append(inLabels, *lbl)
		}
	}

	if len(inLabels) == 0 {
		secCtxLabel, err = client.GetLabels(int(id))
		if err != nil {
			return nil, fmt.Errorf("error while retrieving security context labels "+
				"for ID %d: %s", id, err)
		}
		if secCtxLabel == nil {
			return nil, fmt.Errorf("ID %d not found", id)
		}
	} else {
		lbls := types.LabelSlice2LabelsMap(inLabels)
		srcSHA256Sum, err := lbls.SHA256Sum()
		if err != nil {
			return nil, err
		}
		secCtxLabel, err = client.GetLabelsBySHA256(srcSHA256Sum)
		if err != nil {
			return nil, fmt.Errorf("error while retrieving security context labels "+
				"for labels %q: %s", strings.Join(slice, ", "), err)
		}
		if secCtxLabel == nil {
			return nil, fmt.Errorf("ID not found for labels %q", strings.Join(slice, ", "))
		}
	}

	return secCtxLabel.Labels.ToSlice(), nil
}

func verifyPolicy(ctx *cli.Context) {
	srcInSlice := ctx.StringSlice("source")
	dstInSlice := ctx.StringSlice("destination")

	srcSlice, err := parseAllowedSlice(srcInSlice)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid source: %s\n", err)
		return
	}

	dstSlice, err := parseAllowedSlice(dstInSlice)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid destination: %s\n", err)
		return
	}

	searchCtx := types.SearchContext{
		Trace: true,
		From:  srcSlice,
		To:    dstSlice,
	}

	scr, err := client.PolicyCanConsume(&searchCtx)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while retrieving policy consume result: %s\n", err)
		return
	}
	bytes.NewBuffer(scr.Logging).WriteTo(os.Stdout)
}
