// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package eventqueue implements a queue-based system for event processing in a
// generic fashion in a first-in, first-out manner. There are several important
// properties for an eventqueue. An eventqueue may be implemented in a blocking
// manner, such that only one event is able to be consumed at a time per event
// queue. This is useful in the case for ensuring that certain types of events
// do not run concurrently. An EventQueue may be closed, in which case all
// events which are queued up, but have not been processed, will be cancelled
// (i.e., not ran). It is guaranteed that no events will be scheduled onto an
// EventQueue after it has been closed; if any event is attempted to be
// scheduled onto an EventQueue after it has been closed, it will be cancelled
// immediately. For any event to be processed by the EventQueue, it must
// implement the EventHandler interface. This allows for different types of
// events to be processed by anything which chooses to utilize an EventQueue.
package eventqueue
