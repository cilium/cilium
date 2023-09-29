package main

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/reconciler"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

var SysctlCell = cell.Module(
	"sysctl",
	"sysctl settings",

	statedb.NewProtectedTableCell[*SysctlSetting]("sysctl", SysctlKeyIndex, SysctlStatusIndex),

	cell.Provide(newSysctl),

	// Provide the dependencies to the reconciler.
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
	),

	// Create and register the reconciler.
	cell.Invoke(reconciler.Register[*SysctlSetting]),
)

//
// The Sysctl API
//

type Sysctl struct {
	db    *statedb.DB
	table statedb.RWTable[*SysctlSetting]
}

func newSysctl(db *statedb.DB, table statedb.RWTable[*SysctlSetting]) *Sysctl {
	return &Sysctl{db, table}
}

func (s *Sysctl) Set(key, value string) {
	txn := s.db.WriteTxn(s.table)
	s.table.Insert(txn, &SysctlSetting{Key: key, Value: value, Status: reconciler.StatusPending()})
	txn.Commit()
}

func (s *Sysctl) Wait(ctx context.Context) error {
	return reconciler.WaitForReconciliation(
		ctx,
		s.db,
		s.table,
		SysctlStatusIndex,
	)
}

//
// Sysctl setting and indexes
//

type SysctlSetting struct {
	Key    string
	Value  string
	Status reconciler.Status
}

func (s *SysctlSetting) GetStatus() reconciler.Status {
	return s.Status
}

func (s *SysctlSetting) WithStatus(newStatus reconciler.Status) *SysctlSetting {
	s2 := *s
	s2.Status = newStatus
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

//
// Sysctl reconciliation target
//

type sysctlTestTarget struct {
}

func fakeProcFile(s *SysctlSetting) (*os.File, error) {
	return os.OpenFile(fakeProcPath+"/"+s.Key, os.O_RDWR|os.O_CREATE, 0644)
}

func (sysctlTestTarget) Init(context.Context) error {
	return nil
}

func (t *sysctlTestTarget) Delete(_ context.Context, _ statedb.ReadTxn, s *SysctlSetting) error {
	//fmt.Printf("Delete: %s\n", s.Key)
	if err := maybeError(); err != nil {
		return err
	}

	// Real proc of course doesn't allow delete.
	return os.Remove(fakeProcPath + "/" + s.Key)
}

// Sync implements reconciler.Target
func (t *sysctlTestTarget) Sync(_ context.Context, _ statedb.ReadTxn, iter statedb.Iterator[*SysctlSetting]) (outOfSync bool, err error) {
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
	if rand.Intn(3) == 0 {
		return errors.New("some error")
	}
	return nil
}

// Update implements reconciler.Target
func (t *sysctlTestTarget) Update(_ context.Context, _ statedb.ReadTxn, s *SysctlSetting) error {
	//fmt.Printf("Update: %s => %s\n", s.Key, s.Value)
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
