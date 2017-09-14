// +build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/opencontainers/specs"
)

var execCommand = cli.Command{
	Name:  "exec",
	Usage: "execute new process inside the container",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "console",
			Usage: "specify the pty slave path for use with the container",
		},
		cli.StringFlag{
			Name:  "cwd",
			Usage: "current working directory in the container",
		},
		cli.StringSliceFlag{
			Name:  "env, e",
			Usage: "set environment variables",
		},
		cli.BoolFlag{
			Name:  "tty, t",
			Usage: "allocate a pseudo-TTY",
		},
		cli.StringFlag{
			Name:  "user, u",
			Usage: "UID (format: <uid>[:<gid>])",
		},
		cli.StringFlag{
			Name:  "process,p",
			Usage: "path to the process.json",
		},
		cli.BoolFlag{
			Name:  "detach,d",
			Usage: "detach from the container's process",
		},
		cli.StringFlag{
			Name:  "pid-file",
			Value: "",
			Usage: "specify the file to write the process id to",
		},
	},
	Action: func(context *cli.Context) {
		if os.Geteuid() != 0 {
			logrus.Fatal("runc should be run as root")
		}
		status, err := execProcess(context)
		if err != nil {
			logrus.Fatalf("exec failed: %v", err)
		}
		os.Exit(status)
	},
}

func execProcess(context *cli.Context) (int, error) {
	container, err := getContainer(context)
	if err != nil {
		return -1, err
	}
	var (
		detach = context.Bool("detach")
		rootfs = container.Config().Rootfs
	)
	rootuid, err := container.Config().HostUID()
	if err != nil {
		return -1, err
	}
	p, err := getProcess(context, path.Dir(rootfs))
	if err != nil {
		return -1, err
	}
	process := newProcess(*p)
	tty, err := setupIO(process, rootuid, context.String("console"), p.Terminal, detach)
	if err != nil {
		return -1, err
	}
	if err := container.Start(process); err != nil {
		return -1, err
	}
	if pidFile := context.String("pid-file"); pidFile != "" {
		if err := createPidFile(pidFile, process); err != nil {
			process.Signal(syscall.SIGKILL)
			process.Wait()
			return -1, err
		}
	}
	if detach {
		return 0, nil
	}
	handler := newSignalHandler(tty)
	defer handler.Close()
	return handler.forward(process)
}

func getProcess(context *cli.Context, bundle string) (*specs.Process, error) {
	if path := context.String("process"); path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var p specs.Process
		if err := json.NewDecoder(f).Decode(&p); err != nil {
			return nil, err
		}
		return &p, nil
	}
	// process via cli flags
	if err := os.Chdir(bundle); err != nil {
		return nil, err
	}
	spec, _, err := loadSpec(specConfig, runtimeConfig)
	if err != nil {
		return nil, err
	}
	p := spec.Process
	p.Args = context.Args()
	// override the cwd, if passed
	if context.String("cwd") != "" {
		p.Cwd = context.String("cwd")
	}
	// append the passed env variables
	for _, e := range context.StringSlice("env") {
		p.Env = append(p.Env, e)
	}
	// set the tty
	if context.IsSet("tty") {
		p.Terminal = context.Bool("tty")
	}
	// override the user, if passed
	if context.String("user") != "" {
		u := strings.SplitN(context.String("user"), ":", 2)
		if len(u) > 1 {
			gid, err := strconv.Atoi(u[1])
			if err != nil {
				return nil, fmt.Errorf("parsing %s as int for gid failed: %v", u[1], err)
			}
			p.User.GID = uint32(gid)
		}
		uid, err := strconv.Atoi(u[0])
		if err != nil {
			return nil, fmt.Errorf("parsing %s as int for uid failed: %v", u[0], err)
		}
		p.User.UID = uint32(uid)
	}
	return &p, nil
}
