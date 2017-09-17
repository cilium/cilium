// +build linux

package libcontainer

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/system"
)

type parentProcess interface {
	// pid returns the pid for the running process.
	pid() int

	// start starts the process execution.
	start() error

	// send a SIGKILL to the process and wait for the exit.
	terminate() error

	// wait waits on the process returning the process state.
	wait() (*os.ProcessState, error)

	// startTime return's the process start time.
	startTime() (string, error)

	signal(os.Signal) error

	externalDescriptors() []string

	setExternalDescriptors(fds []string)
}

type setnsProcess struct {
	cmd           *exec.Cmd
	parentPipe    *os.File
	childPipe     *os.File
	cgroupPaths   map[string]string
	config        *initConfig
	fds           []string
	process       *Process
	bootstrapData io.Reader
}

func (p *setnsProcess) startTime() (string, error) {
	return system.GetProcessStartTime(p.pid())
}

func (p *setnsProcess) signal(sig os.Signal) error {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return errors.New("os: unsupported signal type")
	}
	return syscall.Kill(p.pid(), s)
}

func (p *setnsProcess) start() (err error) {
	defer p.parentPipe.Close()
	err = p.cmd.Start()
	p.childPipe.Close()
	if err != nil {
		return newSystemError(err)
	}
	if p.bootstrapData != nil {
		if _, err := io.Copy(p.parentPipe, p.bootstrapData); err != nil {
			return newSystemError(err)
		}
	}
	if err = p.execSetns(); err != nil {
		return newSystemError(err)
	}
	if len(p.cgroupPaths) > 0 {
		if err := cgroups.EnterPid(p.cgroupPaths, p.pid()); err != nil {
			return newSystemError(err)
		}
	}
	if err := json.NewEncoder(p.parentPipe).Encode(p.config); err != nil {
		return newSystemError(err)
	}
	if err := syscall.Shutdown(int(p.parentPipe.Fd()), syscall.SHUT_WR); err != nil {
		return newSystemError(err)
	}
	// wait for the child process to fully complete and receive an error message
	// if one was encoutered
	var ierr *genericError
	if err := json.NewDecoder(p.parentPipe).Decode(&ierr); err != nil && err != io.EOF {
		return newSystemError(err)
	}
	if ierr != nil {
		p.wait()
		return newSystemError(ierr)
	}
	return nil
}

// execSetns runs the process that executes C code to perform the setns calls
// because setns support requires the C process to fork off a child and perform the setns
// before the go runtime boots, we wait on the process to die and receive the child's pid
// over the provided pipe.
func (p *setnsProcess) execSetns() error {
	status, err := p.cmd.Process.Wait()
	if err != nil {
		p.cmd.Wait()
		return newSystemError(err)
	}
	if !status.Success() {
		p.cmd.Wait()
		return newSystemError(&exec.ExitError{ProcessState: status})
	}
	var pid *pid
	if err := json.NewDecoder(p.parentPipe).Decode(&pid); err != nil {
		p.cmd.Wait()
		return newSystemError(err)
	}
	process, err := os.FindProcess(pid.Pid)
	if err != nil {
		return err
	}
	p.cmd.Process = process
	p.process.ops = p
	return nil
}

// terminate sends a SIGKILL to the forked process for the setns routine then waits to
// avoid the process becomming a zombie.
func (p *setnsProcess) terminate() error {
	if p.cmd.Process == nil {
		return nil
	}
	err := p.cmd.Process.Kill()
	if _, werr := p.wait(); err == nil {
		err = werr
	}
	return err
}

func (p *setnsProcess) wait() (*os.ProcessState, error) {
	err := p.cmd.Wait()

	// Return actual ProcessState even on Wait error
	return p.cmd.ProcessState, err
}

func (p *setnsProcess) pid() int {
	return p.cmd.Process.Pid
}

func (p *setnsProcess) externalDescriptors() []string {
	return p.fds
}

func (p *setnsProcess) setExternalDescriptors(newFds []string) {
	p.fds = newFds
}

type initProcess struct {
	cmd        *exec.Cmd
	parentPipe *os.File
	childPipe  *os.File
	config     *initConfig
	manager    cgroups.Manager
	container  *linuxContainer
	fds        []string
	process    *Process
}

func (p *initProcess) pid() int {
	return p.cmd.Process.Pid
}

func (p *initProcess) externalDescriptors() []string {
	return p.fds
}

func (p *initProcess) start() (err error) {
	defer p.parentPipe.Close()
	err = p.cmd.Start()
	p.process.ops = p
	p.childPipe.Close()
	if err != nil {
		p.process.ops = nil
		return newSystemError(err)
	}
	// Save the standard descriptor names before the container process
	// can potentially move them (e.g., via dup2()).  If we don't do this now,
	// we won't know at checkpoint time which file descriptor to look up.
	fds, err := getPipeFds(p.pid())
	if err != nil {
		return newSystemError(err)
	}
	p.setExternalDescriptors(fds)

	// Do this before syncing with child so that no children
	// can escape the cgroup
	if err := p.manager.Apply(p.pid()); err != nil {
		return newSystemError(err)
	}
	defer func() {
		if err != nil {
			// TODO: should not be the responsibility to call here
			p.manager.Destroy()
		}
	}()
	if p.config.Config.Hooks != nil {
		s := configs.HookState{
			Version: p.container.config.Version,
			ID:      p.container.id,
			Pid:     p.pid(),
			Root:    p.config.Config.Rootfs,
		}
		for _, hook := range p.config.Config.Hooks.Prestart {
			if err := hook.Run(s); err != nil {
				return newSystemError(err)
			}
		}
	}
	if err := p.createNetworkInterfaces(); err != nil {
		return newSystemError(err)
	}
	if err := p.sendConfig(); err != nil {
		return newSystemError(err)
	}
	// wait for the child process to fully complete and receive an error message
	// if one was encoutered
	var ierr *genericError
	if err := json.NewDecoder(p.parentPipe).Decode(&ierr); err != nil && err != io.EOF {
		return newSystemError(err)
	}
	if ierr != nil {
		return newSystemError(ierr)
	}
	return nil
}

func (p *initProcess) wait() (*os.ProcessState, error) {
	err := p.cmd.Wait()
	if err != nil {
		return p.cmd.ProcessState, err
	}
	// we should kill all processes in cgroup when init is died if we use host PID namespace
	if p.cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWPID == 0 {
		killCgroupProcesses(p.manager)
	}
	return p.cmd.ProcessState, nil
}

func (p *initProcess) terminate() error {
	if p.cmd.Process == nil {
		return nil
	}
	err := p.cmd.Process.Kill()
	if _, werr := p.wait(); err == nil {
		err = werr
	}
	return err
}

func (p *initProcess) startTime() (string, error) {
	return system.GetProcessStartTime(p.pid())
}

func (p *initProcess) sendConfig() error {
	// send the state to the container's init process then shutdown writes for the parent
	if err := json.NewEncoder(p.parentPipe).Encode(p.config); err != nil {
		return err
	}
	// shutdown writes for the parent side of the pipe
	return syscall.Shutdown(int(p.parentPipe.Fd()), syscall.SHUT_WR)
}

func (p *initProcess) createNetworkInterfaces() error {
	for _, config := range p.config.Config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}
		n := &network{
			Network: *config,
		}
		if err := strategy.create(n, p.pid()); err != nil {
			return err
		}
		p.config.Networks = append(p.config.Networks, n)
	}
	return nil
}

func (p *initProcess) signal(sig os.Signal) error {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return errors.New("os: unsupported signal type")
	}
	return syscall.Kill(p.pid(), s)
}

func (p *initProcess) setExternalDescriptors(newFds []string) {
	p.fds = newFds
}

func getPipeFds(pid int) ([]string, error) {
	fds := make([]string, 3)

	dirPath := filepath.Join("/proc", strconv.Itoa(pid), "/fd")
	for i := 0; i < 3; i++ {
		f := filepath.Join(dirPath, strconv.Itoa(i))
		target, err := os.Readlink(f)
		if err != nil {
			return fds, err
		}
		fds[i] = target
	}
	return fds, nil
}

// InitializeIO creates pipes for use with the process's STDIO
// and returns the opposite side for each
func (p *Process) InitializeIO(rootuid int) (i *IO, err error) {
	var fds []uintptr
	i = &IO{}
	// cleanup in case of an error
	defer func() {
		if err != nil {
			for _, fd := range fds {
				syscall.Close(int(fd))
			}
		}
	}()
	// STDIN
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	fds = append(fds, r.Fd(), w.Fd())
	p.Stdin, i.Stdin = r, w
	// STDOUT
	if r, w, err = os.Pipe(); err != nil {
		return nil, err
	}
	fds = append(fds, r.Fd(), w.Fd())
	p.Stdout, i.Stdout = w, r
	// STDERR
	if r, w, err = os.Pipe(); err != nil {
		return nil, err
	}
	fds = append(fds, r.Fd(), w.Fd())
	p.Stderr, i.Stderr = w, r
	// change ownership of the pipes incase we are in a user namespace
	for _, fd := range fds {
		if err := syscall.Fchown(int(fd), rootuid, rootuid); err != nil {
			return nil, err
		}
	}
	return i, nil
}
