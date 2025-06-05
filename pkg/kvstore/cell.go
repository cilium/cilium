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

		cell.Provide(func(in struct {
			cell.In

			Logger    *slog.Logger
			Lifecycle cell.Lifecycle
			Config    Config
			Opts      ExtraOptions `optional:"true"`
		}) Client {
			// Propagate the options to the global variables for backward compatibility
			option.Config.KVStore = in.Config.KVStore
			option.Config.KVStoreOpt = in.Config.KVStoreOpt
			option.Config.KVstoreLeaseTTL = in.Config.KVStoreLeaseTTL
			option.Config.KVstoreMaxConsecutiveQuorumErrors = in.Config.KVstoreMaxConsecutiveQuorumErrors

			if in.Config.KVStore == DisabledBackendName {
				return &clientImpl{enabled: false}
			}

			cl := &clientImpl{
				enabled: true, cfg: in.Config, opts: in.Opts,
				logger: in.Logger.With(logfields.BackendName, in.Config.KVStore),
			}

			in.Lifecycle.Append(cl)
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
