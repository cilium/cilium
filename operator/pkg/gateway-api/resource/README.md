# Resource Registry

This directory contains the files for the Gateway API reconciler Resource Registry, which holds a Resource per Kubernetes Kind that the Gateway API reconciler needs to handle.

## Resource

A resource is an interface designed to hold various details about a Kubernetes Kind, including things like a pointer to an empty instance of the concrete type (used for controller-runtime Manager things), whether the Resource has status, and whether it should be Indexed or Watched.

## ResourceConfig

This struct is actually stored in the `helpers` module, but it is key to how ResourceRegistry works. 

It is intended to serve as the central struct that holds details about which optional resources are enabled, and various other details or strings that are used in those cases.

## Adding a new Resource

To add a new Resource, you need to do a few steps:

1. Determine if the resource is optional, and if so, add a new fields to `helpers.ResourceConfig` to cover it.
2. Create a file for the Resource in `resource`. Use one of the existing Resources as a template.
3. If the resource has a `status` stanza, set `HandleStatus` accordingly.
4. If the resource needs one or more indexes, add the index to `indexers`, then set up `ShouldIndex` and `GetIndexes` accordingly. Note that Indexers _must not_ require a Kubernetes client, or else we will be unable to add that watch handler to the tests, since in the tests, you need to add indexes during the building of the client.
5. If the resource needs a WatchHandler (which it probably does), add the watch handler to `handlers`, and set up `ShouldWatch` and `GetWatchers` correctly.
6. Add any other details required. Please edit this part if you add new functionality to the Resource Registry.

