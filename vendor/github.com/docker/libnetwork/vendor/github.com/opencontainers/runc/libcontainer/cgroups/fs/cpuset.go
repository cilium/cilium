// +build linux

package fs

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
)

type CpusetGroup struct {
}

func (s *CpusetGroup) Name() string {
	return "cpuset"
}

func (s *CpusetGroup) Apply(d *cgroupData) error {
	dir, err := d.path("cpuset")
	if err != nil && !cgroups.IsNotFound(err) {
		return err
	}
	return s.ApplyDir(dir, d.config, d.pid)
}

func (s *CpusetGroup) Set(path string, cgroup *configs.Cgroup) error {
	if cgroup.CpusetCpus != "" {
		if err := writeFile(path, "cpuset.cpus", cgroup.CpusetCpus); err != nil {
			return err
		}
	}
	if cgroup.CpusetMems != "" {
		if err := writeFile(path, "cpuset.mems", cgroup.CpusetMems); err != nil {
			return err
		}
	}
	return nil
}

func (s *CpusetGroup) Remove(d *cgroupData) error {
	return removePath(d.path("cpuset"))
}

func (s *CpusetGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}

func (s *CpusetGroup) ApplyDir(dir string, cgroup *configs.Cgroup, pid int) error {
	// This might happen if we have no cpuset cgroup mounted.
	// Just do nothing and don't fail.
	if dir == "" {
		return nil
	}
	root, err := getCgroupRoot()
	if err != nil {
		return err
	}
	if err := s.ensureParent(dir, root); err != nil {
		return err
	}
	// the default values inherit from parent cgroup are already set in
	// s.ensureParent, cover these if we have our own
	if err := s.Set(dir, cgroup); err != nil {
		return err
	}
	// because we are not using d.join we need to place the pid into the procs file
	// unlike the other subsystems
	if err := writeFile(dir, "cgroup.procs", strconv.Itoa(pid)); err != nil {
		return err
	}

	return nil
}

func (s *CpusetGroup) getSubsystemSettings(parent string) (cpus []byte, mems []byte, err error) {
	if cpus, err = ioutil.ReadFile(filepath.Join(parent, "cpuset.cpus")); err != nil {
		return
	}
	if mems, err = ioutil.ReadFile(filepath.Join(parent, "cpuset.mems")); err != nil {
		return
	}
	return cpus, mems, nil
}

// ensureParent makes sure that the parent directory of current is created
// and populated with the proper cpus and mems files copied from
// it's parent.
func (s *CpusetGroup) ensureParent(current, root string) error {
	parent := filepath.Dir(current)
	if filepath.Clean(parent) == root {
		return nil
	}
	if err := s.ensureParent(parent, root); err != nil {
		return err
	}
	if err := os.MkdirAll(current, 0755); err != nil {
		return err
	}
	return s.copyIfNeeded(current, parent)
}

// copyIfNeeded copies the cpuset.cpus and cpuset.mems from the parent
// directory to the current directory if the file's contents are 0
func (s *CpusetGroup) copyIfNeeded(current, parent string) error {
	var (
		err                      error
		currentCpus, currentMems []byte
		parentCpus, parentMems   []byte
	)

	if currentCpus, currentMems, err = s.getSubsystemSettings(current); err != nil {
		return err
	}
	if parentCpus, parentMems, err = s.getSubsystemSettings(parent); err != nil {
		return err
	}

	if s.isEmpty(currentCpus) {
		if err := writeFile(current, "cpuset.cpus", string(parentCpus)); err != nil {
			return err
		}
	}
	if s.isEmpty(currentMems) {
		if err := writeFile(current, "cpuset.mems", string(parentMems)); err != nil {
			return err
		}
	}
	return nil
}

func (s *CpusetGroup) isEmpty(b []byte) bool {
	return len(bytes.Trim(b, "\n")) == 0
}
