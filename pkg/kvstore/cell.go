// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"cmp"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// DisabledBackendName disables the kvstore client.
const DisabledBackendName = ""

// Cell returns a cell which provides a promise for the global kvstore client.
func Cell(defaultBackend string) cell.Cell {
	return cell.Module(
		"kvstore-client",
		"KVStore Client",

		cell.Config(Config{
			KVStore:                           defaultBackend,
			KVStoreOpt:                        make(map[string]string),
			KVStoreConnectivityTimeout:        defaults.KVstoreConnectivityTimeout,
			KVStoreLeaseTTL:                   defaults.KVstoreLeaseTTL,
			KVStorePeriodicSync:               defaults.KVstorePeriodicSync,
			KVstoreMaxConsecutiveQuorumErrors: defaults.KVstoreMaxConsecutiveQuorumErrors,
		}),

		cell.Provide(func(in struct {
			cell.In

			Logger    *slog.Logger
			Lifecycle cell.Lifecycle
			Config    Config
			Opts      ExtraOptions `optional:"true"`
		}) Client {
			// Set the global variables, to allow for a gradual migration.
			defaultClientSet = make(chan struct{})

			if in.Config.KVStore == DisabledBackendName {
				return &clientImpl{enabled: false, cfg: in.Config}
			}

			in.Opts.LeaseTTL = cmp.Or(in.Opts.LeaseTTL, in.Config.KVStoreLeaseTTL)
			in.Opts.MaxConsecutiveQuorumErrors = cmp.Or(in.Opts.MaxConsecutiveQuorumErrors,
				in.Config.KVstoreMaxConsecutiveQuorumErrors)

			cl := &clientImpl{
				enabled: true, cfg: in.Config, opts: in.Opts,
				logger: in.Logger.With(logfields.BackendName, in.Config.KVStore),
			}

			in.Lifecycle.Append(cl)
			return cl
		}),

		cell.Invoke(Config.Validate),
	)
}

type Config struct {
	KVStore                           string
	KVStoreOpt                        map[string]string
	KVStoreConnectivityTimeout        time.Duration
	KVStoreLeaseTTL                   time.Duration
	KVStorePeriodicSync               time.Duration
	KVstoreMaxConsecutiveQuorumErrors uint
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(option.KVStore, def.KVStore, "Key-value store type")

	flags.StringToString(option.KVStoreOpt, def.KVStoreOpt,
		"Key-value store options e.g. etcd.address=127.0.0.1:4001")

	flags.Duration(option.KVstoreConnectivityTimeout, def.KVStoreConnectivityTimeout,
		"Time after which an incomplete kvstore operation is considered failed")

	flags.Duration(option.KVstoreLeaseTTL, def.KVStoreLeaseTTL,
		"Time-to-live for the KVstore lease.")

	flags.Duration(option.KVstorePeriodicSync, def.KVStorePeriodicSync,
		"Periodic KVstore synchronization interval")

	flags.Uint(option.KVstoreMaxConsecutiveQuorumErrorsName, def.KVstoreMaxConsecutiveQuorumErrors,
		"Max acceptable kvstore consecutive quorum errors before recreating the etcd connection")
}

func (cfg Config) Validate() error {
	if cfg.KVStoreLeaseTTL > defaults.KVstoreLeaseMaxTTL || cfg.KVStoreLeaseTTL < defaults.LockLeaseTTL {
		return fmt.Errorf("%s does not lie in required range (%v - %v)",
			option.KVstoreLeaseTTL, defaults.LockLeaseTTL, defaults.KVstoreLeaseMaxTTL)
	}

	return nil
}
