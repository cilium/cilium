#!/usr/bin/env bash
set -e
set -x

# !! This script is meant for use in CI build use only !!

KERNEL=$(uname -s)

# Use doas in place of sudo for OpenBSD.
SUDO="sudo"
if [ "${KERNEL}" == "OpenBSD" ]; then
    SUDO="doas"

    # Configure a WireGuard interface.
    doas ifconfig wg0 create
    doas ifconfig wg0 up
fi

if [ "${KERNEL}" == "FreeBSD" ]; then
    # Configure a WireGuard interface.
    sudo ifconfig wg create name wg0
    sudo ifconfig wg0 up
fi

if [ "${KERNEL}" == "Linux" ]; then
    # Configure a WireGuard interface.
    sudo ip link add wg0 type wireguard
    sudo ip link set up wg0
fi

# Set up wireguard-go on all OSes.
git clone https://git.zx2c4.com/wireguard-go
cd wireguard-go

if [ "${KERNEL}" == "Linux" ]; then
    # Bypass Linux compilation restriction.
    make
else
    # Build directly to avoid Makefile.
    go build -o wireguard-go
fi

${SUDO} mv ./wireguard-go /usr/local/bin/wireguard-go
cd ..
${SUDO} rm -rf ./wireguard-go
