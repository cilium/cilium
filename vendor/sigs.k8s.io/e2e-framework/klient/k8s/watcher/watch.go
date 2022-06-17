/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package watcher

import (
	"context"

	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	cr "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/e2e-framework/klient/k8s"
)

// EventHandlerFuncs is an adaptor to let you easily specify as many or
// as few of functions to invoke while getting notification from watcher
type EventHandlerFuncs struct {
	addFunc     func(obj interface{})
	updateFunc  func(newObj interface{})
	deleteFunc  func(obj interface{})
	watcher     watch.Interface
	ListOptions *cr.ListOptions
	K8sObject   k8s.ObjectList
	Cfg         *rest.Config
}

// EventHandler can handle notifications for events that happen to a resource.
// Start will be waiting for the events notification which is responsible
// for invoking the registered user defined functions.
// Stop used to stop the watcher.
type EventHandler interface {
	Start(ctx context.Context)
	Stop()
}

// Start triggers the registered methods based on the event received for
// particular k8s resources
func (e *EventHandlerFuncs) Start(ctx context.Context) error {
	// check if context is valid and that it has not been cancelled.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	cl, err := cr.NewWithWatch(e.Cfg, cr.Options{})
	if err != nil {
		return err
	}

	w, err := cl.Watch(ctx, e.K8sObject, e.ListOptions)
	if err != nil {
		return err
	}

	// set watcher object
	e.watcher = w

	go func() {
		for {
			select {
			case <-ctx.Done():
				if ctx.Err() != nil {
					return
				}
			case event := <-e.watcher.ResultChan():
				// retrieve the event type
				eventType := event.Type

				switch eventType {
				case watch.Added:
					// calls AddFunc if it's not nil.
					if e.addFunc != nil {
						e.addFunc(event.Object)
					}
				case watch.Modified:
					// calls UpdateFunc if it's not nil.
					if e.updateFunc != nil {
						e.updateFunc(event.Object)
					}
				case watch.Deleted:
					// calls DeleteFunc if it's not nil.
					if e.deleteFunc != nil {
						e.deleteFunc(event.Object)
					}
				}
			}
		}
	}()

	return nil
}

// Stop triggers stopping a particular k8s watch resources
func (e *EventHandlerFuncs) Stop() {
	e.watcher.Stop()
}

// SetAddFunc used to set action on create event
func (e *EventHandlerFuncs) WithAddFunc(addfn func(obj interface{})) *EventHandlerFuncs {
	e.addFunc = addfn
	return e
}

// SetUpdateFunc sets action for any update events
func (e *EventHandlerFuncs) WithUpdateFunc(updatefn func(updated interface{})) *EventHandlerFuncs {
	e.updateFunc = updatefn
	return e
}

// SetDeleteFunc sets action for delete events
func (e *EventHandlerFuncs) WithDeleteFunc(deletefn func(obj interface{})) *EventHandlerFuncs {
	e.deleteFunc = deletefn
	return e
}
