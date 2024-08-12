// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysctl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/afero"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/time"
)

// reconciliationTimeout is the maximum time available for reconciling
// sysctl kernel parameters with the desired state in statedb[Sysctl].
const reconciliationTimeout = time.Second

type Sysctl interface {
	// Disable disables the given sysctl parameter.
	// It blocks until the parameter has been actually set to "0",
	// or timeouts after reconciliationTimeout.
	Disable(name string) error

	// Enable enables the given sysctl parameter.
	// It blocks until the parameter has been actually set to "1",
	// or timeouts after reconciliationTimeout.
	Enable(name string) error

	// Write writes the given sysctl parameter.
	// It blocks until the parameter has been actually set to val,
	// or timeouts after reconciliationTimeout.
	Write(name string, val string) error

	// WriteInt writes the given integer type sysctl parameter.
	// It blocks until the parameter has been actually set to val,
	// or timeouts after reconciliationTimeout.
	WriteInt(name string, val int64) error

	// ApplySettings applies all settings in sysSettings.
	// After applying all settings, it blocks until the parameters have been
	// reconciled, or timeouts after reconciliationTimeout.
	ApplySettings(sysSettings []tables.Sysctl) error

	// Read reads the given sysctl parameter.
	Read(name string) (string, error)

	// ReadInt reads the given sysctl parameter, return an int64 value.
	ReadInt(name string) (int64, error)
}

// reconcilingSysctl is a Sysctl implementation that uses reconciliation to
// ensure that the desired state is applied. It is the preffered implementation
// for any binary with hive infrastructure.
type reconcilingSysctl struct {
	db       *statedb.DB
	settings statedb.RWTable[*tables.Sysctl]

	fs     afero.Fs
	procFs string
}

func newReconcilingSysctl(
	db *statedb.DB,
	settings statedb.RWTable[*tables.Sysctl],
	cfg Config,
	fs afero.Fs,
	_ reconciler.Reconciler[*tables.Sysctl], // needed to enforce the correct hive ordering
) Sysctl {
	db.RegisterTable(settings)
	return &reconcilingSysctl{db, settings, fs, cfg.ProcFs}
}

func (sysctl *reconcilingSysctl) Disable(name string) error {
	txn := sysctl.db.WriteTxn(sysctl.settings)
	_, _, _ = sysctl.settings.Insert(txn, &tables.Sysctl{
		Name:   name,
		Val:    "0",
		Status: reconciler.StatusPending(),
	})
	txn.Commit()

	return sysctl.waitForReconciliation(name)
}

func (sysctl *reconcilingSysctl) Enable(name string) error {
	txn := sysctl.db.WriteTxn(sysctl.settings)
	_, _, _ = sysctl.settings.Insert(txn, &tables.Sysctl{
		Name:   name,
		Val:    "1",
		Status: reconciler.StatusPending(),
	})
	txn.Commit()

	return sysctl.waitForReconciliation(name)
}

func (sysctl *reconcilingSysctl) Write(name string, val string) error {
	txn := sysctl.db.WriteTxn(sysctl.settings)
	_, _, _ = sysctl.settings.Insert(txn, &tables.Sysctl{
		Name:   name,
		Val:    val,
		Status: reconciler.StatusPending(),
	})
	txn.Commit()

	return sysctl.waitForReconciliation(name)
}

func (sysctl *reconcilingSysctl) WriteInt(name string, val int64) error {
	txn := sysctl.db.WriteTxn(sysctl.settings)
	_, _, _ = sysctl.settings.Insert(txn, &tables.Sysctl{
		Name:   name,
		Val:    strconv.FormatInt(val, 10),
		Status: reconciler.StatusPending(),
	})
	txn.Commit()

	return sysctl.waitForReconciliation(name)
}

func (sysctl *reconcilingSysctl) ApplySettings(sysSettings []tables.Sysctl) error {
	txn := sysctl.db.WriteTxn(sysctl.settings)
	for _, s := range sysSettings {
		_, _, _ = sysctl.settings.Insert(txn, s.Clone().SetStatus(reconciler.StatusPending()))
	}
	txn.Commit()

	var errs []error
	for _, s := range sysSettings {
		errs = append(errs, sysctl.waitForReconciliation(s.Name))
	}

	return errors.Join(errs...)
}

func (sysctl *reconcilingSysctl) Read(name string) (string, error) {
	path, err := parameterPath(sysctl.procFs, name)
	if err != nil {
		return "", err
	}

	val, err := readSysctl(sysctl.fs, path)
	if err != nil {
		return "", err
	}

	return val, nil
}

func (sysctl *reconcilingSysctl) ReadInt(name string) (int64, error) {
	val, err := sysctl.Read(name)
	if err != nil {
		return -1, err
	}

	v, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return -1, err
	}

	return v, nil
}

type directSysctl struct {
	fs     afero.Fs
	procFs string
}

// NewDirectSysctl creates a Sysctl implementation that directly interacts with the given `fs`.
// It doesn't reconcile and should only be used when using the reconciling variant is not available.
func NewDirectSysctl(fs afero.Fs, procFs string) Sysctl {
	return &directSysctl{fs, procFs}
}

func (ay *directSysctl) Disable(name string) error {
	return ay.WriteInt(name, 0)
}

func (ay *directSysctl) Enable(name string) error {
	return ay.WriteInt(name, 1)
}

func (ay *directSysctl) Write(name string, value string) error {
	path, err := parameterPath(ay.procFs, name)
	if err != nil {
		return err
	}

	// Check if the value is already set to the desired value.
	val, err := ay.Read(name)
	if err != nil {
		return fmt.Errorf("could not read the sysctl file %s: %w", path, err)
	}
	// If the value is already set, return.
	if strings.TrimRight(string(val), "\n") == value {
		return nil
	}

	f, err := ay.fs.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("could not open the sysctl file %s: %w", path, err)
	}
	defer f.Close()

	if _, err := io.WriteString(f, value); err != nil {
		return fmt.Errorf("could not write to the sysctl file %s: %w",
			path, err)
	}
	return nil
}

func (ay *directSysctl) WriteInt(name string, val int64) error {
	return ay.Write(name, strconv.FormatInt(val, 10))
}

func (ay *directSysctl) ApplySettings(sysSettings []tables.Sysctl) error {
	for _, s := range sysSettings {
		if err := ay.Write(s.Name, s.Val); err != nil {
			return err
		}
	}

	return nil
}

func (ay *directSysctl) Read(name string) (string, error) {
	path, err := parameterPath(ay.procFs, name)
	if err != nil {
		return "", err
	}

	f, err := ay.fs.Open(path)
	if err != nil {
		return "", fmt.Errorf("could not open the sysctl file %s: %w", path, err)
	}
	defer f.Close()

	val, err := safeio.ReadAllLimit(f, safeio.KB)
	if err != nil {
		return "", fmt.Errorf("could not read the systctl file %s: %w", path, err)
	}

	return strings.TrimRight(string(val), "\n"), nil
}

func (ay *directSysctl) ReadInt(name string) (int64, error) {
	val, err := ay.Read(name)
	if err != nil {
		return -1, err
	}

	v, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return -1, err
	}

	return v, nil
}

// parameterElemRx matches an element of a sysctl parameter.
var parameterElemRx = regexp.MustCompile(`(?i)\A[-0-9_a-z]+\z`)

// parameterPath returns the path to the sysctl file for parameter name.
//
// It should by used directly only by binaries that do not rely on the
// hive and cells framework, like cilium-cni and cilium-health.
func parameterPath(procFs, name string) (string, error) {
	elems := strings.Split(name, ".")
	for _, elem := range elems {
		if !parameterElemRx.MatchString(elem) {
			return "", fmt.Errorf("invalid sysctl parameter: %q", name)
		}
	}
	return filepath.Join(append([]string{procFs, "sys"}, elems...)...), nil
}

// writeSysctl writes a value in a sysctl parameter loacated at path.
//
// It should by used directly only by binaries that do not rely on the
// hive and cells framework, like cilium-cni and cilium-health.
func writeSysctl(fs afero.Fs, path, value string) error {
	f, err := fs.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("could not open the sysctl file %s: %w", path, err)
	}
	defer f.Close()

	if _, err := io.WriteString(f, value); err != nil {
		return fmt.Errorf("could not write to the sysctl file %s: %w",
			path, err)
	}
	return nil
}

// readSysctl reads a value from a sysctl parameter located at path.
//
// It should by used directly only by binaries that do not rely on the
// hive and cells framework, like cilium-cni and cilium-health.
func readSysctl(fs afero.Fs, path string) (string, error) {
	f, err := fs.Open(path)
	if err != nil {
		return "", fmt.Errorf("could not open the sysctl file %s: %w", path, err)
	}
	defer f.Close()

	val, err := safeio.ReadAllLimit(f, safeio.KB)
	if err != nil {
		return "", fmt.Errorf("could not read the systctl file %s: %w", path, err)
	}

	return strings.TrimRight(string(val), "\n"), nil
}

func (sysctl *reconcilingSysctl) waitForReconciliation(name string) error {
	t := time.NewTimer(reconciliationTimeout)
	defer t.Stop()

	var err error
	for {
		obj, _, watch, _ := sysctl.settings.GetWatch(sysctl.db.ReadTxn(), tables.SysctlNameIndex.Query(name))
		if obj.Status.Kind == reconciler.StatusKindDone {
			// already reconciled
			return nil
		}

		select {
		case <-t.C:
			return fmt.Errorf("timeout waiting for parameter %s reconciliation: %w", name, err)
		case <-watch:
			if obj.Status.Kind == reconciler.StatusKindDone {
				return nil
			}
			if obj.Status.Kind == reconciler.StatusKindError {
				err = errors.New(obj.Status.Error)
			}
		}
	}
}
