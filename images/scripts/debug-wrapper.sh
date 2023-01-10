#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

/usr/bin/dlv \
    --listen=:2345 \
    --headless=true \
    --log=true \
    --log-output=debugger,debuglineerr,gdbwire,lldbout,rpc \
    --accept-multiclient \
    --api-version=2 \
    exec "${0}-bin" -- "$@"
