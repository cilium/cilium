#!/usr/bin/env bash

# Wait for systemd-resolved to become available
for ((i = 0 ; i < 10; i++)); do

    if systemctl status systemd-resolved > /dev/null 2>&1; then
        break
    fi
    sleep 5s
    echo "Waiting for systemd-resolved to come up..."
done

systemctl status systemd-resolved || true
