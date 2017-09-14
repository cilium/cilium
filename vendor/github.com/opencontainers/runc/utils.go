// +build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/specs"
)

const wildcard = -1

var allowedDevices = []*configs.Device{
	// allow mknod for any device
	{
		Type:        'c',
		Major:       wildcard,
		Minor:       wildcard,
		Permissions: "m",
	},
	{
		Type:        'b',
		Major:       wildcard,
		Minor:       wildcard,
		Permissions: "m",
	},
	{
		Path:        "/dev/console",
		Type:        'c',
		Major:       5,
		Minor:       1,
		Permissions: "rwm",
	},
	{
		Path:        "/dev/tty0",
		Type:        'c',
		Major:       4,
		Minor:       0,
		Permissions: "rwm",
	},
	{
		Path:        "/dev/tty1",
		Type:        'c',
		Major:       4,
		Minor:       1,
		Permissions: "rwm",
	},
	// /dev/pts/ - pts namespaces are "coming soon"
	{
		Path:        "",
		Type:        'c',
		Major:       136,
		Minor:       wildcard,
		Permissions: "rwm",
	},
	{
		Path:        "",
		Type:        'c',
		Major:       5,
		Minor:       2,
		Permissions: "rwm",
	},
	// tuntap
	{
		Path:        "",
		Type:        'c',
		Major:       10,
		Minor:       200,
		Permissions: "rwm",
	},
}

var container libcontainer.Container

func containerPreload(context *cli.Context) error {
	c, err := getContainer(context)
	if err != nil {
		return err
	}
	container = c
	return nil
}

// loadFactory returns the configured factory instance for execing containers.
func loadFactory(context *cli.Context) (libcontainer.Factory, error) {
	root := context.GlobalString("root")
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return libcontainer.New(abs, libcontainer.Cgroupfs, func(l *libcontainer.LinuxFactory) error {
		l.CriuPath = context.GlobalString("criu")
		return nil
	})
}

// getContainer returns the specified container instance by loading it from state
// with the default factory.
func getContainer(context *cli.Context) (libcontainer.Container, error) {
	factory, err := loadFactory(context)
	if err != nil {
		return nil, err
	}
	container, err := factory.Load(context.GlobalString("id"))
	if err != nil {
		return nil, err
	}
	return container, nil
}

// fatal prints the error's details if it is a libcontainer specific error type
// then exits the program with an exit status of 1.
func fatal(err error) {
	if lerr, ok := err.(libcontainer.Error); ok {
		lerr.Detail(os.Stderr)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// getDefaultID returns a string to be used as the container id based on the
// current working directory of the runc process.  This function panics
// if the cwd is unable to be found based on a system error.
func getDefaultID() string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Base(cwd)
}

func getDefaultImagePath(context *cli.Context) string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Join(cwd, "checkpoint")
}

// newProcess returns a new libcontainer Process with the arguments from the
// spec and stdio from the current process.
func newProcess(p specs.Process) *libcontainer.Process {
	return &libcontainer.Process{
		Args: p.Args,
		Env:  p.Env,
		// TODO: fix libcontainer's API to better support uid/gid in a typesafe way.
		User: fmt.Sprintf("%d:%d", p.User.UID, p.User.GID),
		Cwd:  p.Cwd,
	}
}

func dupStdio(process *libcontainer.Process, rootuid int) error {
	process.Stdin = os.Stdin
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
	for _, fd := range []uintptr{
		os.Stdin.Fd(),
		os.Stdout.Fd(),
		os.Stderr.Fd(),
	} {
		if err := syscall.Fchown(int(fd), rootuid, rootuid); err != nil {
			return err
		}
	}
	return nil
}

// If systemd is supporting sd_notify protocol, this function will add support
// for sd_notify protocol from within the container.
func setupSdNotify(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, notifySocket string) {
	mountName := "sdNotify"
	spec.Mounts = append(spec.Mounts, specs.MountPoint{Name: mountName, Path: notifySocket})
	spec.Process.Env = append(spec.Process.Env, fmt.Sprintf("NOTIFY_SOCKET=%s", notifySocket))
	rspec.Mounts[mountName] = specs.Mount{Type: "bind", Source: notifySocket, Options: []string{"bind"}}
}

// If systemd is supporting on-demand socket activation, this function will add support
// for on-demand socket activation for the containerized service.
func setupSocketActivation(spec *specs.LinuxSpec, listenFds string) {
	spec.Process.Env = append(spec.Process.Env, fmt.Sprintf("LISTEN_FDS=%s", listenFds), "LISTEN_PID=1")
}

func destroy(container libcontainer.Container) {
	if err := container.Destroy(); err != nil {
		logrus.Error(err)
	}
}

func setupIO(process *libcontainer.Process, rootuid int, console string, createTTY, detach bool) (*tty, error) {
	// detach and createTty will not work unless a console path is passed
	// so error out here before changing any terminal settings
	if createTTY && detach && console == "" {
		return nil, fmt.Errorf("cannot allocate tty if runc will detach")
	}
	if createTTY {
		return createTty(process, rootuid, console)
	}
	if detach {
		if err := dupStdio(process, rootuid); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return createStdioPipes(process, rootuid)
}

func createPidFile(path string, process *libcontainer.Process) error {
	pid, err := process.Pid()
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%d", pid)
	return err
}
