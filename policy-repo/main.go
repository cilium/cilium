package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/noironetworks/cilium-net/common"
	cnc "github.com/noironetworks/cilium-net/common/cilium-net-client"
	"github.com/noironetworks/cilium-net/common/types"

	log "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/Sirupsen/logrus"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/codegangsta/cli"
)

var (
	Client      *cnc.Client
	ignoredDirs = []string{".git"}
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
			Name:    "dump",
			Aliases: []string{"d"},
			Usage:   "dump policy (sub)tree",
			Action:  dumpPolicy,
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

func loadPolicyDirectory(path string) (*types.PolicyNode, error) {
	log.Debugf("Entering directory %s...", path)

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var node *types.PolicyNode

	// process all files first
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		if p, err := loadPolicyFile(path + "/" + f.Name()); err != nil {
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
			if common.StringInSlice(f.Name(), ignoredDirs) {
				continue
			}
			subpath := path + "/" + f.Name()
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

	log.Debugf("Leaving directory %s...", path)

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
	} else {
		log.Debugf("Constructed policy object for import %+v\n", node)

		if err := Client.PolicyAdd(node.Name, *node); err != nil {
			fmt.Fprintf(os.Stderr, "Could not import policy directory %s: %s\n", path, err)
		}
	}
}

func validatePolicy(ctx *cli.Context) {
	path := getPath(ctx)
	if _, err := loadPolicyDirectory(path); err != nil {
		fmt.Fprintf(os.Stderr, "Validation of %s failed\n%s\n", path, err)
	} else {
		fmt.Printf("All policy elements are valid.\n")
	}
}

func dumpPolicy(ctx *cli.Context) {
	path := "io.cilium"

	n, err := Client.PolicyGet(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not retrieve policy for: %s: %s\n", path, err)
		return
	}

	if b, err := json.MarshalIndent(n, "", "  "); err != nil {
		fmt.Fprintf(os.Stderr, "Could not marshal response: %s\n", err)
	} else {
		fmt.Printf("%s\n", b)
	}
}

func initEnv(ctx *cli.Context) error {
	if ctx.Bool("debug") {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	log.SetOutput(os.Stderr)

	c, err := cnc.NewDefaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		return fmt.Errorf("Error while creating cilium-client: %s\n", err)
	}

	Client = c

	return nil
}
