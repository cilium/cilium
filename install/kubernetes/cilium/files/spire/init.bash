# shellcheck disable=SC2086
# shellcheck disable=SC2139
set -e

echo "Waiting for spire process to start"
while ! pgrep spire-server > /dev/null; do sleep 5; done

SPIRE_SERVER_ROOT_PATH="/proc/$(pgrep spire-server)/root"

alias spire_server="${SPIRE_SERVER_ROOT_PATH}/opt/spire/bin/spire-server"
SOCKET_PATH="${SPIRE_SERVER_ROOT_PATH}/tmp/spire-server/private/api.sock"
SOCKET_FLAG="-socketPath ${SOCKET_PATH}"

echo "Checking spire-server status"
while ! spire_server entry show ${SOCKET_FLAG} &> /dev/null; do
  echo "Waiting for spire-server to start..."
  sleep 5
done

echo "Spire Server is up, initializing cilium spire entries..."

AGENT_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/ns/{{ .Values.authentication.mutual.spire.install.namespace }}/sa/spire-agent"
AGENT_SELECTORS="-selector k8s_psat:agent_ns:{{ .Values.authentication.mutual.spire.install.namespace }} -selector k8s_psat:agent_sa:spire-agent"
CILIUM_AGENT_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/cilium-agent"
CILIUM_AGENT_SELECTORS="-selector k8s:ns:{{ .Release.Namespace }} -selector k8s:sa:{{ .Values.serviceAccounts.cilium.name }}"
CILIUM_OPERATOR_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/cilium-operator"
CILIUM_OPERATOR_SELECTORS="-selector k8s:ns:{{ .Release.Namespace }} -selector k8s:sa:{{ .Values.serviceAccounts.operator.name }}"

while pgrep spire-server > /dev/null;
do
  echo "Ensuring agent entry"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $AGENT_SPIFFE_ID $AGENT_SELECTORS | grep -q "Found 0 entries" &> /dev/null; then
    spire_server entry create ${SOCKET_FLAG} -spiffeID $AGENT_SPIFFE_ID $AGENT_SELECTORS -node
  fi

  echo "Ensuring cilium-agent entry (required for the delegated identity to work)"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $CILIUM_AGENT_SPIFFE_ID $CILIUM_AGENT_SELECTORS | grep -q "Found 0 entries" &> /dev/null; then
    spire_server entry create ${SOCKET_FLAG} -spiffeID $CILIUM_AGENT_SPIFFE_ID -parentID $AGENT_SPIFFE_ID $CILIUM_AGENT_SELECTORS
  fi

  echo "Ensuring cilium-operator entry (required for creating SPIFFE identities)"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $CILIUM_OPERATOR_SPIFFE_ID $CILIUM_OPERATOR_SELECTORS | grep -q "Found 0 entries" &> /dev/null; then
    spire_server entry create ${SOCKET_FLAG} -spiffeID $CILIUM_OPERATOR_SPIFFE_ID -parentID $AGENT_SPIFFE_ID $CILIUM_OPERATOR_SELECTORS
  fi

  echo "Cilium Spire entries are initialized successfully or already in-sync"
  sleep 30;
done
