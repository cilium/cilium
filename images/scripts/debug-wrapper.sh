#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

DEBUG_PORT="${DEBUG_PORT:=2345}"
DEBUG_CONTINUE="${DEBUG_CONTINUE:=false}"

/usr/bin/dlv \
    --listen=":${DEBUG_PORT}" \
    --headless=true \
    --continue="${DEBUG_CONTINUE}" \
    --log=true \
    --log-output=debugger,debuglineerr,gdbwire,lldbout,rpc \
    --accept-multiclient \
    --api-version=2 \
    exec "${0}-bin" -- "$@"
