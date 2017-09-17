// +build linux

package fs

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
)

var (
	subsystems = subsystemSet{
		&CpusetGroup{},
		&DevicesGroup{},
		&MemoryGroup{},
		&CpuGroup{},
		&CpuacctGroup{},
		&BlkioGroup{},
		&HugetlbGroup{},
		&NetClsGroup{},
		&NetPrioGroup{},
		&PerfEventGroup{},
		&FreezerGroup{},
	}
	CgroupProcesses  = "cgroup.procs"
	HugePageSizes, _ = cgroups.GetHugePageSize()
)

var errSubsystemDoesNotExist = errors.New("cgroup: subsystem does not exist")

type subsystemSet []subsystem

func (s subsystemSet) Get(name string) (subsystem, error) {
	for _, ss := range s {
		if ss.Name() == name {
			return ss, nil
		}
	}
	return nil, errSubsystemDoesNotExist
}

type subsystem interface {
	// Name returns the name of the subsystem.
	Name() string
	// Returns the stats, as 'stats', corresponding to the cgroup under 'path'.
	GetStats(path string, stats *cgroups.Stats) error
	// Removes the cgroup represented by 'cgroupData'.
	Remove(*cgroupData) error
	// Creates and joins the cgroup represented by 'cgroupData'.
	Apply(*cgroupData) error
	// Set the cgroup represented by cgroup.
	Set(path string, cgroup *configs.Cgroup) error
}

type Manager struct {
	mu      sync.Mutex
	Cgroups *configs.Cgroup
	Paths   map[string]string
}

// The absolute path to the root of the cgroup hierarchies.
var cgroupRootLock sync.Mutex
var cgroupRoot string

// Gets the cgroupRoot.
func getCgroupRoot() (string, error) {
	cgroupRootLock.Lock()
	defer cgroupRootLock.Unlock()

	if cgroupRoot != "" {
		return cgroupRoot, nil
	}

	root, err := cgroups.FindCgroupMountpointDir()
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(root); err != nil {
		return "", err
	}

	cgroupRoot = root
	return cgroupRoot, nil
}

type cgroupData struct {
	root   string
	parent string
	name   string
	config *configs.Cgroup
	pid    int
}

func (m *Manager) Apply(pid int) (err error) {
	if m.Cgroups == nil {
		return nil
	}

	var c = m.Cgroups

	d, err := getCgroupData(m.Cgroups, pid)
	if err != nil {
		return err
	}

	paths := make(map[string]string)
	defer func() {
		if err != nil {
			cgroups.RemovePaths(paths)
		}
	}()
	for _, sys := range subsystems {
		if err := sys.Apply(d); err != nil {
			return err
		}
		// TODO: Apply should, ideally, be reentrant or be broken up into a separate
		// create and join phase so that the cgroup hierarchy for a container can be
		// created then join consists of writing the process pids to cgroup.procs
		p, err := d.path(sys.Name())
		if err != nil {
			if cgroups.IsNotFound(err) {
				continue
			}
			return err
		}
		paths[sys.Name()] = p
	}
	m.Paths = paths

	if paths["cpu"] != "" {
		if err := CheckCpushares(paths["cpu"], c.CpuShares); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) Destroy() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := cgroups.RemovePaths(m.Paths); err != nil {
		return err
	}
	m.Paths = make(map[string]string)
	return nil
}

func (m *Manager) GetPaths() map[string]string {
	m.mu.Lock()
	paths := m.Paths
	m.mu.Unlock()
	return paths
}

func (m *Manager) GetStats() (*cgroups.Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stats := cgroups.NewStats()
	for name, path := range m.Paths {
		sys, err := subsystems.Get(name)
		if err == errSubsystemDoesNotExist || !cgroups.PathExists(path) {
			continue
		}
		if err := sys.GetStats(path, stats); err != nil {
			return nil, err
		}
	}
	return stats, nil
}

func (m *Manager) Set(container *configs.Config) error {
	for name, path := range m.Paths {
		sys, err := subsystems.Get(name)
		if err == errSubsystemDoesNotExist || !cgroups.PathExists(path) {
			continue
		}
		if err := sys.Set(path, container.Cgroups); err != nil {
			return err
		}
	}
	return nil
}

// Freeze toggles the container's freezer cgroup depending on the state
// provided
func (m *Manager) Freeze(state configs.FreezerState) error {
	d, err := getCgroupData(m.Cgroups, 0)
	if err != nil {
		return err
	}
	dir, err := d.path("freezer")
	if err != nil {
		return err
	}
	prevState := m.Cgroups.Freezer
	m.Cgroups.Freezer = state
	freezer, err := subsystems.Get("freezer")
	if err != nil {
		return err
	}
	err = freezer.Set(dir, m.Cgroups)
	if err != nil {
		m.Cgroups.Freezer = prevState
		return err
	}
	return nil
}

func (m *Manager) GetPids() ([]int, error) {
	d, err := getCgroupData(m.Cgroups, 0)
	if err != nil {
		return nil, err
	}

	dir, err := d.path("devices")
	if err != nil {
		return nil, err
	}

	return cgroups.GetPids(dir)
}

func getCgroupData(c *configs.Cgroup, pid int) (*cgroupData, error) {
	root, err := getCgroupRoot()
	if err != nil {
		return nil, err
	}

	return &cgroupData{
		root:   root,
		parent: c.Parent,
		name:   c.Name,
		config: c,
		pid:    pid,
	}, nil
}

func (raw *cgroupData) parentPath(subsystem, mountpoint, root string) (string, error) {
	// Use GetThisCgroupDir instead of GetInitCgroupDir, because the creating
	// process could in container and shared pid namespace with host, and
	// /proc/1/cgroup could point to whole other world of cgroups.
	initPath, err := cgroups.GetThisCgroupDir(subsystem)
	if err != nil {
		return "", err
	}
	// This is needed for nested containers, because in /proc/self/cgroup we
	// see pathes from host, which don't exist in container.
	relDir, err := filepath.Rel(root, initPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(mountpoint, relDir), nil
}

func (raw *cgroupData) path(subsystem string) (string, error) {
	mnt, root, err := cgroups.FindCgroupMountpointAndRoot(subsystem)
	// If we didn't mount the subsystem, there is no point we make the path.
	if err != nil {
		return "", err
	}

	cgPath := filepath.Join(raw.parent, raw.name)
	// If the cgroup name/path is absolute do not look relative to the cgroup of the init process.
	if filepath.IsAbs(cgPath) {
		// Sometimes subsystems can be mounted togethger as 'cpu,cpuacct'.
		return filepath.Join(raw.root, filepath.Base(mnt), cgPath), nil
	}

	parentPath, err := raw.parentPath(subsystem, mnt, root)
	if err != nil {
		return "", err
	}

	return filepath.Join(parentPath, cgPath), nil
}

func (raw *cgroupData) join(subsystem string) (string, error) {
	path, err := raw.path(subsystem)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}
	if err := writeFile(path, CgroupProcesses, strconv.Itoa(raw.pid)); err != nil {
		return "", err
	}
	return path, nil
}

func writeFile(dir, file, data string) error {
	// Normally dir should not be empty, one case is that cgroup subsystem
	// is not mounted, we will get empty dir, and we want it fail here.
	if dir == "" {
		return fmt.Errorf("no such directory for %s.", file)
	}
	return ioutil.WriteFile(filepath.Join(dir, file), []byte(data), 0700)
}

func readFile(dir, file string) (string, error) {
	data, err := ioutil.ReadFile(filepath.Join(dir, file))
	return string(data), err
}

func removePath(p string, err error) error {
	if err != nil {
		return err
	}
	if p != "" {
		return os.RemoveAll(p)
	}
	return nil
}

func CheckCpushares(path string, c int64) error {
	var cpuShares int64

	if c == 0 {
		return nil
	}

	fd, err := os.Open(filepath.Join(path, "cpu.shares"))
	if err != nil {
		return err
	}
	defer fd.Close()

	_, err = fmt.Fscanf(fd, "%d", &cpuShares)
	if err != nil && err != io.EOF {
		return err
	}

	if c > cpuShares {
		return fmt.Errorf("The maximum allowed cpu-shares is %d", cpuShares)
	} else if c < cpuShares {
		return fmt.Errorf("The minimum allowed cpu-shares is %d", cpuShares)
	}

	return nil
}
