// +build linux

package libcontainer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"

	"github.com/docker/docker/pkg/mount"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/cgroups/rootless"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/configs/validate"
	"github.com/opencontainers/runc/libcontainer/utils"

	"golang.org/x/sys/unix"
)

const (
	stateFilename    = "state.json"
	execFifoFilename = "exec.fifo"
)

var idRegex = regexp.MustCompile(`^[\w+-\.]+$`)

// InitArgs returns an options func to configure a LinuxFactory with the
// provided init binary path and arguments.
func InitArgs(args ...string) func(*LinuxFactory) error {
	return func(l *LinuxFactory) (err error) {
		if len(args) > 0 {
			// Resolve relative paths to ensure that its available
			// after directory changes.
			if args[0], err = filepath.Abs(args[0]); err != nil {
				return newGenericError(err, ConfigInvalid)
			}
		}

		l.InitArgs = args
		return nil
	}
}

// SystemdCgroups is an options func to configure a LinuxFactory to return
// containers that use systemd to create and manage cgroups.
func SystemdCgroups(l *LinuxFactory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &systemd.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// Cgroupfs is an options func to configure a LinuxFactory to return
// containers that use the native cgroups filesystem implementation to
// create and manage cgroups.
func Cgroupfs(l *LinuxFactory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &fs.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// RootlessCgroups is an options func to configure a LinuxFactory to
// return containers that use the "rootless" cgroup manager, which will
// fail to do any operations not possible to do with an unprivileged user.
// It should only be used in conjunction with rootless containers.
func RootlessCgroups(l *LinuxFactory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &rootless.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// TmpfsRoot is an option func to mount LinuxFactory.Root to tmpfs.
func TmpfsRoot(l *LinuxFactory) error {
	mounted, err := mount.Mounted(l.Root)
	if err != nil {
		return err
	}
	if !mounted {
		if err := unix.Mount("tmpfs", l.Root, "tmpfs", 0, ""); err != nil {
			return err
		}
	}
	return nil
}

// CriuPath returns an option func to configure a LinuxFactory with the
// provided criupath
func CriuPath(criupath string) func(*LinuxFactory) error {
	return func(l *LinuxFactory) error {
		l.CriuPath = criupath
		return nil
	}
}

// New returns a linux based container factory based in the root directory and
// configures the factory with the provided option funcs.
func New(root string, options ...func(*LinuxFactory) error) (Factory, error) {
	if root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, newGenericError(err, SystemError)
		}
	}
	l := &LinuxFactory{
		Root:      root,
		InitArgs:  []string{"/proc/self/exe", "init"},
		Validator: validate.New(),
		CriuPath:  "criu",
	}
	Cgroupfs(l)
	for _, opt := range options {
		if err := opt(l); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// LinuxFactory implements the default factory interface for linux based systems.
type LinuxFactory struct {
	// Root directory for the factory to store state.
	Root string

	// InitArgs are arguments for calling the init responsibilities for spawning
	// a container.
	InitArgs []string

	// CriuPath is the path to the criu binary used for checkpoint and restore of
	// containers.
	CriuPath string

	// Validator provides validation to container configurations.
	Validator validate.Validator

	// NewCgroupsManager returns an initialized cgroups manager for a single container.
	NewCgroupsManager func(config *configs.Cgroup, paths map[string]string) cgroups.Manager
}

func (l *LinuxFactory) Create(id string, config *configs.Config) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	if err := l.validateID(id); err != nil {
		return nil, err
	}
	if err := l.Validator.Validate(config); err != nil {
		return nil, newGenericError(err, ConfigInvalid)
	}
	containerRoot := filepath.Join(l.Root, id)
	if _, err := os.Stat(containerRoot); err == nil {
		return nil, newGenericError(fmt.Errorf("container with id exists: %v", id), IdInUse)
	} else if !os.IsNotExist(err) {
		return nil, newGenericError(err, SystemError)
	}
	if err := os.MkdirAll(containerRoot, 0711); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	if err := os.Chown(containerRoot, unix.Geteuid(), unix.Getegid()); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	if config.Rootless {
		RootlessCgroups(l)
	}
	c := &linuxContainer{
		id:            id,
		root:          containerRoot,
		config:        config,
		initArgs:      l.InitArgs,
		criuPath:      l.CriuPath,
		cgroupManager: l.NewCgroupsManager(config.Cgroups, nil),
	}
	c.state = &stoppedState{c: c}
	return c, nil
}

func (l *LinuxFactory) Load(id string) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	containerRoot := filepath.Join(l.Root, id)
	state, err := l.loadState(containerRoot, id)
	if err != nil {
		return nil, err
	}
	r := &nonChildProcess{
		processPid:       state.InitProcessPid,
		processStartTime: state.InitProcessStartTime,
		fds:              state.ExternalDescriptors,
	}
	// We have to use the RootlessManager.
	if state.Rootless {
		RootlessCgroups(l)
	}
	c := &linuxContainer{
		initProcess:          r,
		initProcessStartTime: state.InitProcessStartTime,
		id:                   id,
		config:               &state.Config,
		initArgs:             l.InitArgs,
		criuPath:             l.CriuPath,
		cgroupManager:        l.NewCgroupsManager(state.Config.Cgroups, state.CgroupPaths),
		root:                 containerRoot,
		created:              state.Created,
	}
	c.state = &loadedState{c: c}
	if err := c.refreshState(); err != nil {
		return nil, err
	}
	return c, nil
}

func (l *LinuxFactory) Type() string {
	return "libcontainer"
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
func (l *LinuxFactory) StartInitialization() (err error) {
	var (
		pipefd, rootfd int
		consoleSocket  *os.File
		envInitPipe    = os.Getenv("_LIBCONTAINER_INITPIPE")
		envStateDir    = os.Getenv("_LIBCONTAINER_STATEDIR")
		envConsole     = os.Getenv("_LIBCONTAINER_CONSOLE")
	)

	// Get the INITPIPE.
	pipefd, err = strconv.Atoi(envInitPipe)
	if err != nil {
		return fmt.Errorf("unable to convert _LIBCONTAINER_INITPIPE=%s to int: %s", envInitPipe, err)
	}

	var (
		pipe = os.NewFile(uintptr(pipefd), "pipe")
		it   = initType(os.Getenv("_LIBCONTAINER_INITTYPE"))
	)
	defer pipe.Close()

	// Only init processes have STATEDIR.
	rootfd = -1
	if it == initStandard {
		if rootfd, err = strconv.Atoi(envStateDir); err != nil {
			return fmt.Errorf("unable to convert _LIBCONTAINER_STATEDIR=%s to int: %s", envStateDir, err)
		}
	}

	if envConsole != "" {
		console, err := strconv.Atoi(envConsole)
		if err != nil {
			return fmt.Errorf("unable to convert _LIBCONTAINER_CONSOLE=%s to int: %s", envConsole, err)
		}
		consoleSocket = os.NewFile(uintptr(console), "console-socket")
		defer consoleSocket.Close()
	}

	// clear the current process's environment to clean any libcontainer
	// specific env vars.
	os.Clearenv()

	defer func() {
		// We have an error during the initialization of the container's init,
		// send it back to the parent process in the form of an initError.
		if werr := utils.WriteJSON(pipe, syncT{procError}); werr != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if werr := utils.WriteJSON(pipe, newSystemError(err)); werr != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}()
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic from initialization: %v, %v", e, string(debug.Stack()))
		}
	}()

	i, err := newContainerInit(it, pipe, consoleSocket, rootfd)
	if err != nil {
		return err
	}

	// If Init succeeds, syscall.Exec will not return, hence none of the defers will be called.
	return i.Init()
}

func (l *LinuxFactory) loadState(root, id string) (*State, error) {
	f, err := os.Open(filepath.Join(root, stateFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newGenericError(fmt.Errorf("container %q does not exist", id), ContainerNotExists)
		}
		return nil, newGenericError(err, SystemError)
	}
	defer f.Close()
	var state *State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	return state, nil
}

func (l *LinuxFactory) validateID(id string) error {
	if !idRegex.MatchString(id) {
		return newGenericError(fmt.Errorf("invalid id format: %v", id), InvalidIdFormat)
	}

	return nil
}
