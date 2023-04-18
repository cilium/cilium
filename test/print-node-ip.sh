#!/usr/bin/env bash

set -e

case "$(uname -s)" in
    Darwin*) ipconfig getifaddr en0 ;;
    *)       hostname -I | cut -d " " -f 1
esac
