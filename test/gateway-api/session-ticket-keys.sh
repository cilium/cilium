#!/usr/bin/env bash

set -euo pipefail

namespace=session-ticket-e2e
gateway_name=session-ticket
ticket_secret_name=session-ticket-keys
hostname=session-ticket.example.com
target_namespace=cilium-secrets
target_secret_pattern='tls.sessionticket.key'
workdir=$(mktemp -d)
port_forward_pids=()

cleanup() {
    for pid in "${port_forward_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$workdir"
}

trap cleanup EXIT

fail() {
    echo "session-ticket E2E: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

for command in cilium kubectl jq openssl timeout; do
    require_command "$command"
done

create_tls_secret() {
    kubectl -n "$namespace" create secret tls session-ticket-tls \
        --cert="$workdir/server.crt" \
        --key="$workdir/server.key" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

create_ticket_secret() {
    local current_key=$1
    local previous_key=${2:-}
    local command=(
        kubectl -n "$namespace" create secret generic "$ticket_secret_name"
        --from-file=tls.sessionticket.key="$current_key"
        --dry-run=client -o yaml
    )

    if [[ -n "$previous_key" ]]; then
        command+=(--from-file=tls.sessionticket.key.1="$previous_key")
    fi

    "${command[@]}" | kubectl apply -f - >/dev/null
}

wait_for_gateway() {
    kubectl wait -n "$namespace" --for=condition=Accepted=True \
        "gateway.gateway.networking.k8s.io/$gateway_name" --timeout=5m
    kubectl wait -n "$namespace" --for=condition=Programmed=True \
        "gateway.gateway.networking.k8s.io/$gateway_name" --timeout=5m
}

wait_for_load_balancer() {
    for _ in $(seq 1 60); do
        load_balancer_ip=$(kubectl -n "$namespace" get service \
            "cilium-gateway-$gateway_name" \
            -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
        if [[ -n "$load_balancer_ip" ]]; then
            export load_balancer_ip
            return
        fi
        sleep 2
    done
    fail "Gateway LoadBalancer did not receive an IP"
}

gateway_pods() {
    kubectl -n kube-system get pods -o json |
        jq -r '.items[] | select(any(.spec.containers[]?; .name == "cilium-envoy")) |
            select(.status.phase == "Running") | .metadata.name' | sort
}

agent_for_node() {
    local node=$1
    kubectl -n kube-system get pods -o json |
        jq -r --arg node "$node" '.items[] |
            select(.spec.nodeName == $node) |
            select(any(.spec.containers[]?; .name == "cilium-agent")) |
            .metadata.name' | head -n 1
}

listener_port() {
    local agent=$1
    local listener_line

    listener_line=$(kubectl -n kube-system exec "$agent" -c cilium-agent -- \
        cilium-dbg envoy admin listeners |
        grep -F "/$namespace/cilium-gateway-$gateway_name/" | head -n 1 || true)
    [[ -n "$listener_line" ]] || return 1
    echo "${listener_line##*:}"
}

wait_for_listener_port() {
    local agent=$1
    local port

    for _ in $(seq 1 90); do
        if port=$(listener_port "$agent"); then
            echo "$port"
            return
        fi
        sleep 2
    done
    fail "Gateway listener was not active on agent $agent"
}

stop_port_forwards() {
    for pid in "${port_forward_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    port_forward_pids=()
}

start_port_forwards() {
    local pod_a pod_b node_a node_b agent_a agent_b port_a port_b
    local local_port_a=28001
    local local_port_b=28002

    stop_port_forwards
    mapfile -t envoy_pods < <(gateway_pods)
    [[ ${#envoy_pods[@]} -ge 2 ]] || fail "fewer than two running Envoy pods"
    pod_a=${envoy_pods[0]}
    pod_b=${envoy_pods[1]}
    node_a=$(kubectl -n kube-system get pod "$pod_a" -o jsonpath='{.spec.nodeName}')
    node_b=$(kubectl -n kube-system get pod "$pod_b" -o jsonpath='{.spec.nodeName}')
    agent_a=$(agent_for_node "$node_a")
    agent_b=$(agent_for_node "$node_b")
    [[ -n "$agent_a" && -n "$agent_b" ]] || fail "could not find Cilium agents for Envoy pods"
    port_a=$(wait_for_listener_port "$agent_a")
    port_b=$(wait_for_listener_port "$agent_b")

    kubectl -n kube-system port-forward "pod/$pod_a" "$local_port_a:$port_a" \
        >"$workdir/port-forward-a.log" 2>&1 &
    port_forward_pids+=("$!")
    kubectl -n kube-system port-forward "pod/$pod_b" "$local_port_b:$port_b" \
        >"$workdir/port-forward-b.log" 2>&1 &
    port_forward_pids+=("$!")

    for _ in $(seq 1 30); do
        if (echo >/dev/tcp/127.0.0.1/$local_port_a) 2>/dev/null &&
            (echo >/dev/tcp/127.0.0.1/$local_port_b) 2>/dev/null; then
            export endpoint_a="127.0.0.1:$local_port_a"
            export endpoint_b="127.0.0.1:$local_port_b"
            return
        fi
        sleep 1
    done
    fail "Envoy port-forwards did not become ready"
}

run_tls_probe() {
    local label=$1
    local protocol=$2
    local endpoint=$3
    local session_in=$4
    local session_out=$5
    local expected=$6
    local output status=0 handshake http_status
    local command=(
        openssl s_client
        -connect "$endpoint"
        -servername "$hostname"
        -verify_hostname "$hostname"
        -verify_return_error
        -CAfile "$workdir/server.crt"
        "-$protocol"
        -ign_eof
    )

    if [[ -n "$session_in" ]]; then
        command+=(-sess_in "$session_in")
    fi
    if [[ -n "$session_out" ]]; then
        command+=(-sess_out "$session_out")
    fi

    output=$(printf 'HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \
        "$hostname" | timeout 20s "${command[@]}" 2>&1) || status=$?
    handshake=$(printf '%s\n' "$output" | grep -m 1 -E '^(New|Reused), TLS' || true)
    http_status=$(printf '%s\n' "$output" | grep -m 1 -E '^HTTP/' || true)
    echo "$label: ${handshake:-no handshake}, ${http_status:-no HTTP response}"

    [[ "$handshake" == "$expected,"* ]] ||
        fail "$label expected $expected handshake, got ${handshake:-none} (exit $status)"
    [[ -n "$http_status" ]] || fail "$label did not receive an HTTP response"
}

wait_for_synced_ticket_secret() {
    local require_previous=$1
    local expected_key=$2
    for _ in $(seq 1 90); do
        if kubectl -n "$target_namespace" get secrets -o json |
            jq -e --arg key "$target_secret_pattern" --arg previous "${target_secret_pattern}.1" \
                --arg expected_key "$expected_key" --argjson require_previous "$require_previous" '
                [.items[] | select(.data[$key] != null)] as $tickets |
                ($tickets | length == 1) and
                ($tickets[0].data[$key] == $expected_key) and
                (if $require_previous then $tickets[0].data[$previous] != null
                 else $tickets[0].data[$previous] == null end)' >/dev/null; then
            return
        fi
        sleep 2
    done
    fail "synchronized ticket Secret did not reach the expected rotation state"
}

envoy_snapshot() {
    kubectl -n kube-system get pods -o json |
        jq -c '[.items[] | select(any(.spec.containers[]?; .name == "cilium-envoy")) |
            {name: .metadata.name, uid: .metadata.uid,
             restarts: ([.status.containerStatuses[]? | select(.name == "cilium-envoy") |
                         .restartCount] | add // 0)}] | sort_by(.name)'
}

require_disabled_configuration() {
    local config
    config=$(kubectl -n kube-system get configmap cilium-config -o json)
    jq -e '(.data["gateway-api-session-ticket-keys-secret-name"] // "") == "" and
           (.data["gateway-api-session-ticket-keys-secret-namespace"] // "") == ""' \
        <<<"$config" >/dev/null || fail "session ticket configuration is unexpectedly enabled"
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$workdir/server.key" -out "$workdir/server.crt" \
    -subj "/CN=$hostname" -addext "subjectAltName=DNS:$hostname" \
    >/dev/null 2>&1
openssl rand 80 >"$workdir/key-a"
openssl rand 80 >"$workdir/key-b"

kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
create_tls_secret
kubectl apply -f - <<EOF >/dev/null
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: $gateway_name
  namespace: $namespace
spec:
  gatewayClassName: cilium
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    hostname: $hostname
    tls:
      mode: Terminate
      certificateRefs:
      - name: session-ticket-tls
    allowedRoutes:
      namespaces:
        from: Same
EOF
wait_for_gateway
wait_for_load_balancer
require_disabled_configuration
start_port_forwards

echo "disabled baseline"
for protocol in tls1_2 tls1_3; do
    run_tls_probe "disabled fresh $protocol" "$protocol" "$endpoint_a" "" \
        "$workdir/disabled-$protocol.session" New
    run_tls_probe "disabled cross-Envoy $protocol" "$protocol" "$endpoint_b" \
        "$workdir/disabled-$protocol.session" "" New
done

echo "enabling shared session ticket keys"
create_ticket_secret "$workdir/key-a"
cilium upgrade --reuse-values --chart-directory=untrusted/install/kubernetes/cilium \
    --helm-set=gatewayAPI.sessionTicketKeysSecret.name="$ticket_secret_name" \
    --helm-set=gatewayAPI.sessionTicketKeysSecret.namespace="$namespace"
cilium status --wait --interactive=false
kubectl -n kube-system rollout status deployment/cilium-operator --timeout=5m
wait_for_synced_ticket_secret false "$(base64 -w0 <"$workdir/key-a")"
wait_for_gateway
start_port_forwards

echo "shared key cross-Envoy resumption"
for protocol in tls1_2 tls1_3; do
    run_tls_probe "shared fresh $protocol" "$protocol" "$endpoint_a" "" \
        "$workdir/shared-$protocol.session" New
    run_tls_probe "shared same-Envoy $protocol" "$protocol" "$endpoint_a" \
        "$workdir/shared-$protocol.session" "" Reused
    run_tls_probe "shared cross-Envoy $protocol" "$protocol" "$endpoint_b" \
        "$workdir/shared-$protocol.session" "" Reused
done

before_rotation=$(envoy_snapshot)
echo "rotating session ticket keys"
create_ticket_secret "$workdir/key-b" "$workdir/key-a"
wait_for_synced_ticket_secret true "$(base64 -w0 <"$workdir/key-b")"
run_tls_probe "rotation preserves old TLS 1.2 ticket" tls1_2 "$endpoint_b" \
    "$workdir/shared-tls1_2.session" "" Reused
run_tls_probe "rotation uses new TLS 1.2 key" tls1_2 "$endpoint_a" "" \
    "$workdir/rotated-tls1_2.session" New
run_tls_probe "rotation cross-Envoy new TLS 1.2 ticket" tls1_2 "$endpoint_b" \
    "$workdir/rotated-tls1_2.session" "" Reused
[[ "$before_rotation" == "$(envoy_snapshot)" ]] ||
    fail "Envoy pods changed during key rotation"

echo "removing the previous session ticket key"
create_ticket_secret "$workdir/key-b"
wait_for_synced_ticket_secret false "$(base64 -w0 <"$workdir/key-b")"
run_tls_probe "removed old TLS 1.2 ticket" tls1_2 "$endpoint_b" \
    "$workdir/shared-tls1_2.session" "" New

echo "restarting Envoy DaemonSet"
kubectl -n kube-system rollout restart daemonset/cilium-envoy
kubectl -n kube-system rollout status daemonset/cilium-envoy --timeout=5m
start_port_forwards
run_tls_probe "post-restart shared TLS 1.2 ticket" tls1_2 "$endpoint_b" \
    "$workdir/rotated-tls1_2.session" "" Reused

echo "LoadBalancer path"
run_tls_probe "LoadBalancer fresh TLS 1.2" tls1_2 "$load_balancer_ip:443" "" \
    "$workdir/load-balancer-tls1_2.session" New
run_tls_probe "LoadBalancer resumed TLS 1.2" tls1_2 "$load_balancer_ip:443" \
    "$workdir/load-balancer-tls1_2.session" "" Reused

echo "session-ticket E2E passed"
