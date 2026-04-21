// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// watchhandlers holds functions that return closures that are used as
// handler.TypedEventHandler[client.Object, reconcile.Request]
// in controller-runtime Watch() calls. Each type of object has up to one watchhandler per
// reconciler it's used in.
//
// # The watchhandler closures all have the signature
//
// ```
// func(ctx context.Context, a client.Object) []reconcile.Request
// ```
//
// and take a single client.Object that's been changed (added, deleted or updated), and
// figure out what, if any of the reconciled objects are relevant, and return a reconcile.Request
// for each reconciled object that needs to be rereconcilied.
//
// In this way, for example, an update in a HTTPRoute can be traced back to the Gateway
// that HTTPRoute is a child of, and, if that Gateway is relevant to Cilium, we trigger
// reconciliation for that Gateway (which will update config for the HTTPRoute we just saw
// as well as any other relevant config that's changed since last time).
//
// The watchhandler functions that generate the closures should generally take a Kubernetes client and an slog logger, and
// may take other parameters (like the name of an index to look up or similar). Indexing via the
// `indexers` package happens _before_ the watches get checked (actually, before the object enters
// the controller-runtime cache), so it's okay to use indexes in these functions. Index names should
// be stored as constants in the `indexers` package as well.
//
// It's expected that the watchhandler functions will be called, and the _closure_ function stored by
// the caller so that we can programmatically build out the list of Watch calls for a reconciler.
package watchhandlers
