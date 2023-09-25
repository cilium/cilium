package main

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/reconciler"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

type SysctlSetting struct {
	Key   string
	Value string

	status reconciler.Status
}

func (s *SysctlSetting) GetStatus() reconciler.Status {
	return s.status
}

func (s *SysctlSetting) WithStatus(newStatus reconciler.Status) *SysctlSetting {
	s2 := *s
	s2.status = newStatus
	return &s2
}

var (
	SysctlKeyIndex = statedb.Index[*SysctlSetting, string]{
		Name: "key",
		FromObject: func(s *SysctlSetting) index.KeySet {
			return index.NewKeySet(index.String(s.Key))
		},
		FromKey: index.String,
		Unique:  true,
	}
	SysctlStatusIndex = reconciler.NewStatusIndex[*SysctlSetting]()
)

var Cell = cell.Module(
	"sysctl",
	"sysctl settings",

	statedb.NewTableCell[*SysctlSetting]("sysctl", SysctlKeyIndex, SysctlStatusIndex),

	cell.ProvidePrivate(
		func() reconciler.Target[*SysctlSetting] { return &sysctlTestTarget{} },
		func() reconciler.Config {
			return reconciler.Config{
				FullReconcilationInterval: 10 * time.Second,
				RetryBackoffMinDuration:   time.Second,
				RetryBackoffMaxDuration:   10 * time.Second,
			}
		},
		func() statedb.Index[*SysctlSetting, reconciler.StatusKind] { return SysctlStatusIndex },

		reconciler.New[*SysctlSetting],
	),
	cell.Invoke(func(reconciler.Reconciler[*SysctlSetting]) {}),
)

type sysctlTestTarget struct {
}

func fakeProcFile(s *SysctlSetting) (*os.File, error) {
	return os.OpenFile(fakeProcPath+"/"+s.Key, os.O_RDWR|os.O_CREATE, 0644)
}

func (t *sysctlTestTarget) Delete(s *SysctlSetting) error {
	fmt.Printf("Delete: %s\n", s.Key)
	if err := maybeError(); err != nil {
		return err
	}

	// Real proc of course doesn't allow delete.
	return os.Remove(fakeProcPath + "/" + s.Key)
}

// Sync implements reconciler.Target
func (t *sysctlTestTarget) Sync(iter statedb.Iterator[*SysctlSetting]) (outOfSync bool, err error) {
	if err := maybeError(); err != nil {
		return false, err
	}

	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		var f *os.File
		f, err = fakeProcFile(obj)
		if err != nil {
			return
		}

		var oldValue []byte
		oldValue, err = io.ReadAll(f)

		if string(oldValue) != obj.Value {
			outOfSync = true
			f.Seek(0, 0)
			f.Truncate(int64(len(obj.Value)))
			f.WriteString(obj.Value)
			f.Close()
		}
	}
	return
}

func maybeError() error {
	if rand.Intn(10) == 0 {
		return errors.New("some error")
	}
	return nil
}

// Update implements reconciler.Target
func (t *sysctlTestTarget) Update(s *SysctlSetting) error {
	fmt.Printf("Update: %s => %s\n", s.Key, s.Value)
	if err := maybeError(); err != nil {
		return err
	}

	var f *os.File
	f, err := fakeProcFile(s)
	if err != nil {
		return err
	}
	err = f.Truncate(int64(len(s.Value)))
	if err != nil {
		return err
	}
	_, err = f.WriteString(s.Value)
	if err != nil {
		return err
	}
	return f.Close()
}

var _ reconciler.Target[*SysctlSetting] = &sysctlTestTarget{}
