#!/usr/bin/env bash

main() {
    local cilium_started
    cilium_started=false

    for ((i = 0 ; i < 24; i++)); do
        if cilium-dbg status --brief > /dev/null 2>&1; then
            cilium_started=true
            break
        fi
        sleep 5s
        docker logs cilium | tail --lines=10
        echo "Waiting for Cilium daemon to come up..."
    done

    if [ "$cilium_started" = true ] ; then
        echo 'Cilium successfully started!'
    else
        >&2 echo 'Timeout waiting for Cilium to start...'
        journalctl -u cilium.service --since $(systemctl show -p ActiveEnterTimestamp cilium.service | awk '{print $2 $3}')
        >&2 echo 'Cilium failed to start'
        exit 1
    fi
}

main "$@"
