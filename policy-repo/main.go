package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/noironetworks/cilium-net/bpf/policymap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/bpf"
	cnc "github.com/noironetworks/cilium-net/common/client"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/codegangsta/cli"
	l "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

var (
	Client             *cnc.Client
	ignoredMasksSource = []string{".git"}
	ignoredMasks       []*regexp.Regexp
	log                = l.MustGetLogger("cilium-net-policy-repo")
)

func main() {
	app := cli.NewApp()
	app.Name = "cilium-policy"
	app.Usage = "Cilium Networking Policy Tool"
	app.Version = "0.1.0"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "Enable debug messages",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "validate",
			Aliases: []string{"v"},
			Usage:   "validate a policy (sub)tree",
			Action:  validatePolicy,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "path, p",
					Usage: "Path to directory containing the policy tree",
				},
				cli.BoolFlag{
					Name:  "dump, d",
					Usage: "Dump parsed policy tree after validation",
				},
			},
		},
		{
			Name:    "import",
			Aliases: []string{"i"},
			Usage:   "import a policy (sub)tree",
			Action:  importPolicy,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "path, p",
					Usage: "Path to directory containing the policy tree",
				},
			},
		},
		{
			Name:   "dump",
			Usage:  "dump policy (sub)tree",
			Action: dumpPolicy,
		},
		{
			Name:   "delete",
			Usage:  "delete policy (sub)tree",
			Action: deletePolicy,
		},
		{
			Name:   "get-id",
			Usage:  "lookup security context id",
			Action: getSecID,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "list, l",
					Usage: "List all reserved IDs",
				},
			},
		},
		{
			Name:   "dump-map",
			Usage:  "dump BPF policy map",
			Action: dumpMap,
		},
	}
	app.Before = initEnv
	app.Run(os.Args)
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

func init() {
	ignoredMasks = make([]*regexp.Regexp, len(ignoredMasksSource))

	for i, _ := range ignoredMasksSource {
		ignoredMasks[i] = regexp.MustCompile(ignoredMasksSource[i])
	}
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

func getPath(ctx *cli.Context) string {
	path := ctx.String("path")
	if path == "" {
		path = "."
	}

	return path
}

func importPolicy(ctx *cli.Context) {
	path := getPath(ctx)
	if node, err := loadPolicyDirectory(path); err != nil {
		fmt.Fprintf(os.Stderr, "Could not import policy directory %s: %s\n", path, err)
		os.Exit(1)
	} else {
		log.Debugf("Constructed policy object for import %+v", node)

		// Ignore request if no policies have been found
		if node == nil {
			return
		}

		if err := Client.PolicyAdd(node.Name, node); err != nil {
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
	path := getPath(ctx)
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
	path := "io.cilium"

	n, err := Client.PolicyGet(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not retrieve policy for: %s: %s\n", path, err)
		os.Exit(1)
	}

	prettyPrint(n)
}

func deletePolicy(ctx *cli.Context) {
	path := "io.cilium"

	if err := Client.PolicyDelete(path); err != nil {
		fmt.Fprintf(os.Stderr, "Could not retrieve policy for: %s: %s\n", path, err)
		os.Exit(1)
	}
}

func getSecID(ctx *cli.Context) {
	if ctx.Bool("list") {
		for k, v := range types.ReservedIDMap {
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

func dumpMap(ctx *cli.Context) {
	lbl := ctx.Args().First()

	if lbl != "" {
		if id := types.GetID(lbl); id != types.ID_UNKNOWN {
			lbl = "reserved_" + strconv.Itoa(int(id))
		}
	} else {
		fmt.Fprintf(os.Stderr, "Need ID or label\n")
		os.Exit(1)
	}

	file := common.PolicyMapPath + lbl
	fd, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	m := policymap.PolicyMap{Fd: fd}
	if out, err := m.Dump(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	} else {
		fmt.Println(out)
	}
}

func initEnv(ctx *cli.Context) error {
	if ctx.Bool("debug") {
		common.SetupLOG(log, "DEBUG", "")
	} else {
		common.SetupLOG(log, "INFO", "")
	}

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		os.Exit(1)
	}

	Client = c

	return nil
}
