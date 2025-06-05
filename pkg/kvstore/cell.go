// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
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

// Cell returns a cell which provides the global kvstore client.
func Cell(defaultBackend string) cell.Cell {
	return cell.Module(
		"kvstore-client",
		"KVStore Client",

		cell.Config(Config{
			KVStore:                           defaultBackend,
			KVStoreOpt:                        make(map[string]string),
			KVStoreLeaseTTL:                   defaults.KVstoreLeaseTTL,
			KVstoreMaxConsecutiveQuorumErrors: defaults.KVstoreMaxConsecutiveQuorumErrors,
		}),

		cell.Provide(func(logger *slog.Logger, lc cell.Lifecycle, cfg Config, opts *ExtraOptions) Client {
			// Propagate the options to the global variables for backward compatibility
			option.Config.KVStore = cfg.KVStore
			option.Config.KVStoreOpt = cfg.KVStoreOpt
			option.Config.KVstoreLeaseTTL = cfg.KVStoreLeaseTTL
			option.Config.KVstoreMaxConsecutiveQuorumErrors = cfg.KVstoreMaxConsecutiveQuorumErrors

			if cfg.KVStore == DisabledBackendName {
				return &clientImpl{enabled: false}
			}

			cl := &clientImpl{
				enabled: true, cfg: cfg, opts: opts,
				logger: logger.With(logfields.BackendName, cfg.KVStore),
			}

			lc.Append(cl)
			return cl
		}),
	)
}

type Config struct {
	KVStore                           string
	KVStoreOpt                        map[string]string
	KVStoreLeaseTTL                   time.Duration
	KVstoreMaxConsecutiveQuorumErrors uint
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(option.KVStore, def.KVStore, "Key-value store type")

	flags.StringToString(option.KVStoreOpt, def.KVStoreOpt,
		"Key-value store options e.g. etcd.address=127.0.0.1:4001")

	flags.Duration(option.KVstoreLeaseTTL, def.KVStoreLeaseTTL,
		"Time-to-live for the KVstore lease.")

	flags.Uint(option.KVstoreMaxConsecutiveQuorumErrorsName, def.KVstoreMaxConsecutiveQuorumErrors,
		"Max acceptable kvstore consecutive quorum errors before recreating the etcd connection")
}
