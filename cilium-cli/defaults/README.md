# `defaults/imagedigests.json`

`defaults/imagedigests.json` contains the image digests for well-known images.

The command `cmd/internal/add-image-digests` adds new image digests. For example:

    go run ./cmd/internal/add-image-digests cilium v1.11.0

or

    go run ./cmd/internal/add-image-digests hubble-ui v0.8.5
