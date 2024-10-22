// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package slowg defines an Analyzer that checks for inappropriate use of
// Logger.With() from the log/slog package.
//
// # Analyzer slowg
//
// slowg: check for inappropriate use of Logger.With().
//
// The slowg checker looks for calls to Logger.With() from the log/slog
// package. Logger.With() constructs a new Logger containing the provided
// attributes. The parent logger is cloned when arguments are supplied, which
// is a relatively expensive operation which should not be used in hot code path.
// For example, slowg would report the following call:
//
//	log.With("key", val).Info("message")
//
// And suggest to replace it with the following one:
//
//	log.Info("message", "key", val)
//
// However, the slowg checker does not prevent the use of With and WithGroup.
//
//	wlog := log.With("key", val)             // this is fine
//	wlog.Info("info")                        // this is also fine
//	wlog.With("more", "attr").Debug("debug") // this is flagged as inappropriate use
package slowg
