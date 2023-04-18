set -e

echo "Waiting for spire server to be reachable to start"

ADDR="{{ .Values.auth.mTLS.spire.serverAddress }}"
CONN_TIMEOUT="3"
TIMEOUT="60"

call_tcp_endpoint_with_timeout() {
    local addr="$1"
    local timeout="$2"

    nc -z "$addr" -w "$timeout" &> /dev/null
}

# wait for SPIRE server to be reachable till $TIMEOUT is reached
start_time=$(date +%s)
while true; do
    if call_tcp_endpoint_with_timeout "$ADDR" "$CONN_TIMEOUT"; then
        echo "SPIRE server is reachable"
        break
    fi

    if [ $(( $(date +%s) - start_time )) -gt "$TIMEOUT" ]; then
        echo "Timed out waiting for spire server to be reachable"
        exit 1
    fi

    echo "Waiting for spire server to be reachable"
    sleep 1
done
