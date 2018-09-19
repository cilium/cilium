// Copyright 2018 Authors of Cilium
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

// Package buildqueue provides a basic build queue for objects identified by
// UUID. An object is buildable if it implements GetUUID(). An object can build
// itself if it implements the Builder interface.
//
// Objects with identical UUID will never be built in parallel. The build queue
// will maintain a set of worker threads which will build objects in parallel.
//
// When an object is already queued to be built not being being built yet, any
// further build request will be ignored.
//
// When an object is being actively built and a new build request is enqueued,
// the build request will deferred. It will be scheduled into the build queue
// when the currently ongoing build of that same object has completed.
package buildqueue
