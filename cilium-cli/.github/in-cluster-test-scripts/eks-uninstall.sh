#!/bin/sh

set -x
set -e

# Uninstall Cilium
cilium uninstall --wait
