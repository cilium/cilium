// Copyright 2022 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

// Package watcher is a library for computing the status of kubernetes resource
// objects based on watching object state from a cluster. It keeps watching
// until it is cancelled through the provided context. Updates on the status of
// objects are streamed back to the caller through a channel.
//
// # Watching Resources
//
// In order to watch a set of resources objects, create a StatusWatcher
// and pass in the list of object identifiers to the Watch function.
//
//	import (
//	  "github.com/fluxcd/cli-utils/pkg/kstatus/watcher"
//	)
//
//	ids := []prune.ObjMetadata{
//	  {
//	    GroupKind: schema.GroupKind{
//	      Group: "apps",
//	      Kind: "Deployment",
//	    },
//	    Name: "dep",
//	    Namespace: "default",
//	  }
//	}
//
//	statusWatcher := watcher.NewDefaultStatusWatcher(dynamicClient, mapper)
//	ctx, cancelFunc := context.WithCancel(context.Background())
//	eventCh := statusWatcher.Watch(ctx, ids, watcher.Options{})
//	for e := range eventCh {
//	   // Handle event
//	   if e.Type == event.ErrorEvent {
//	     cancelFunc()
//	     return e.Err
//	   }
//	}
package watcher
