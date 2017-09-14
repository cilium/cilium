<!--[metadata]>
+++
title = "Filesystem storage driver"
description = "Explains how to use the filesystem storage drivers"
keywords = ["registry, service, driver, images, storage,  filesystem"]
[menu.main]
parent="smn_storagedrivers"
+++
<![end-metadata]-->


# Filesystem storage driver

An implementation of the `storagedriver.StorageDriver` interface which uses the local filesystem.

## Parameters

`rootdirectory`: (optional) The absolute path to a root directory tree in which
to store all registry files. The registry stores all its data here so make sure
there is adequate space available. Defaults to `/var/lib/registry`.
`maxthreads`: (optional) The maximum number of simultaneous blocking filesystem
operations permitted within the registry. Each operation spawns a new thread and
may cause thread exhaustion issues if many are done in parallel. Defaults to
`100`, and can be no lower than `25`.
