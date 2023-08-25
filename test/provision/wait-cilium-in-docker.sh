#!/usr/bin/env bash

# Wait for cilium agent to become available
for ((i = 0 ; i < 12; i++)); do
    if cilium status --brief > /dev/null 2>&1; then
        break
    fi
    sleep 5s
    echo "Waiting for Cilium daemon to come up..."
done

echo "Cilium status:"
cilium status || true
