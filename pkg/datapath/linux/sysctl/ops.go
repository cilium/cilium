// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysctl

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

func newOps(log logrus.FieldLogger, fs afero.Fs, cfg Config) reconciler.Operations[*tables.Sysctl] {
	return &ops{log: log, fs: fs, procFs: cfg.ProcFs}
}

type ops struct {
	log    logrus.FieldLogger
	fs     afero.Fs
	procFs string
}

func (ops *ops) Update(ctx context.Context, txn statedb.ReadTxn, s *tables.Sysctl) (changed bool, err error) {
	log := ops.log.WithFields(logrus.Fields{
		logfields.SysParamName:  s.Name,
		logfields.SysParamValue: s.Val,
	})

	path, err := ParameterPath(ops.procFs, s.Name)
	if err != nil {
		if s.IgnoreErr {
			return false, nil
		}
		return false, fmt.Errorf("failed to get full path of sysctl setting %s: %w", s.Name, err)
	}

	val, err := ReadSysctl(ops.fs, path)
	if err != nil {
		if s.IgnoreErr {
			return false, nil
		}
		return false, err
	}
	if val == s.Val {
		return false, nil
	}

	if err := WriteSysctl(ops.fs, path, s.Val); err != nil {
		if s.IgnoreErr {
			warn := "Failed to write sysctl setting"
			if s.Warn != "" {
				warn = s.Warn
			}
			log.Warning(warn)
			return false, nil
		}
		return true, fmt.Errorf("failed to write sysctl setting %s: %w", path, err)
	}

	return true, nil
}

func (ops *ops) Delete(context.Context, statedb.ReadTxn, *tables.Sysctl) error {
	// sysctl settings will never be deleted, just ignored
	return nil
}

func (ops *ops) Prune(context.Context, statedb.ReadTxn, statedb.Iterator[*tables.Sysctl]) error {
	// sysctl settings not in the table will never be pruned, just ignored
	return nil
}
