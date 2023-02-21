#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

DEBUG_PORT="${DEBUG_PORT:=2345}"

/usr/bin/dlv \
    --listen=":${DEBUG_PORT}" \
    --headless=true \
    --log=true \
    --log-output=debugger,debuglineerr,gdbwire,lldbout,rpc \
    --accept-multiclient \
    --api-version=2 \
    exec "${0}-bin" -- "$@"
