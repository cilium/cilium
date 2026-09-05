// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/hubble/relay/server"
)

// Extension adds downstream configuration and server options to the Hubble
// Relay serve command.
//
// Extensions are trusted code linked into a downstream-owned Relay binary.
// They register flags and are configured in the order supplied to [New]. Relay
// serve flags are registered before extension flags, and every extension
// receives the same mutable flag set. Extensions may inspect or modify flags
// registered earlier. Flag registration failures, including duplicate names or
// shorthands, follow pflag's behavior and may panic. The flag set is borrowed
// for the duration of [Extension.RegisterFlags] and must not be retained or
// accessed after that method returns.
//
// Configuration happens after Cobra parses the command and the root command
// initializes logging, but before Relay derives its server options or starts its
// servers. Each extension receives the same mutable Viper instance. Changes made
// before [Extension.Configure] returns are visible to later extensions and to
// configuration reads performed by Relay; they do not affect flag parsing or
// logging that has already occurred. In particular, values written with
// [viper.Viper.Set] take precedence over flags, environment variables,
// configuration files, and defaults.
//
// Relay does not rerun earlier extensions after a later extension changes the
// configuration. Callers must therefore order extensions so later mutations do
// not invalidate configuration or resources already accepted by an earlier
// extension.
//
// Viper is not safe for concurrent reads and writes. Extensions must finish
// accessing it before Configure returns and copy any values needed by runtime
// resources. Relay does not roll back Viper mutations if an extension fails.
//
// Extension server options are appended after the options constructed by the
// serve command, preserving extension and within-extension order. Option
// composition depends on the option: scalar setters typically replace earlier
// values, while interceptor options append to an interceptor chain. The
// package-level [server.DefaultOptions] are applied by [server.New] after every
// option passed by the serve command, including extension options.
//
// Relay owns every non-nil closer returned by a successful
// [Extension.Configure]. If configuration fails, the failing extension must
// release its resources before returning. Later extensions are not configured,
// and Relay rolls back the resources returned by earlier extensions. During
// rollback and normal shutdown, Relay first cancels the shared extension context
// and then calls closers in reverse configuration order.
type Extension interface {
	// Name returns the stable name used to identify the extension in errors and
	// logs. It must be unique among the extensions supplied to New.
	Name() string

	// RegisterFlags adds extension-specific flags during command construction.
	// Relay calls it once for each extension in the order supplied to New and
	// before binding the completed shared flag set to Viper. Lifecycle resources
	// should be created by Configure, where they can be returned for cleanup.
	RegisterFlags(flags *pflag.FlagSet)

	// Configure creates extension resources and server options after command
	// parsing and logging initialization. Relay passes the same derived context
	// and Viper instance to every extension, then reads the resulting serve
	// configuration after every extension succeeds. It cancels the context before
	// invoking any returned closer. Relay applies returned options in slice order.
	// If Configure returns an error, the extension must release any resources it
	// created before returning.
	Configure(ctx context.Context, log *slog.Logger, vp *viper.Viper) ([]server.Option, io.Closer, error)
}

// configuredCloser associates a resource with the extension that owns it so
// cleanup errors can identify which extension failed.
type configuredCloser struct {
	// extensionName identifies the extension that owns closer.
	extensionName string
	// closer releases the resources created by that extension.
	closer io.Closer
}

// configuredExtensions contains the server options and resources produced by
// one successful configuration pass. The caller consumes serverOptions when
// constructing Relay and must call Close once when that Relay run ends.
type configuredExtensions struct {
	// serverOptions preserves extension and within-extension ordering.
	serverOptions []server.Option
	// closers preserves configuration order for reverse-order cleanup.
	closers []configuredCloser
	// cancel stops the context shared by all configured extensions.
	cancel context.CancelFunc
}

// configureExtensions derives a shared lifecycle context and configures each
// extension sequentially against vp. Mutations to vp are therefore visible to
// later extensions and the serve command. If any extension fails, the function
// cancels the shared context, closes resources returned by previously configured
// extensions in reverse order, and joins cleanup failures with the configuration
// error. The failing extension is responsible for its own cleanup. On success,
// the caller owns the returned value and must close it exactly once.
func configureExtensions(ctx context.Context, log *slog.Logger, vp *viper.Viper, extensions []Extension) (*configuredExtensions, error) {
	extensionCtx, cancel := context.WithCancel(ctx)
	configured := &configuredExtensions{cancel: cancel}
	for _, extension := range extensions {
		name := extension.Name()
		serverOptions, closer, err := extension.Configure(extensionCtx, log, vp)
		if err != nil {
			configureErr := fmt.Errorf("configure serve extension %q: %w", name, err)
			if closeErr := configured.Close(); closeErr != nil {
				return nil, errors.Join(configureErr, closeErr)
			}
			return nil, configureErr
		}
		if closer != nil {
			configured.closers = append(configured.closers, configuredCloser{
				extensionName: name,
				closer:        closer,
			})
		}
		configured.serverOptions = append(configured.serverOptions, serverOptions...)
	}
	return configured, nil
}

// Close cancels the context shared by the extensions, then closes every
// extension resource in reverse configuration order. It attempts every close
// and joins any failures, annotating each one with the extension's name.
func (c *configuredExtensions) Close() error {
	c.cancel()
	var errs error
	for _, closer := range slices.Backward(c.closers) {
		if err := closer.closer.Close(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("close serve extension %q: %w", closer.extensionName, err))
		}
	}
	return errs
}
