# shellcheck disable=SC2086
set -e

# Function to get current SPIRE server PID
get_spire_pid() {
  pgrep spire-server 2>/dev/null || echo ""
}

# Function to check if PID is valid and process is running
is_pid_valid() {
  local pid=$1
  [ -n "$pid" ] && [ -d "/proc/$pid" ] && [ -f "/proc/$pid/cmdline" ] && grep -q "spire-server" "/proc/$pid/cmdline" 2>/dev/null
}

echo "Waiting for spire process to start"
SPIRE_PID=""
while [ -z "$SPIRE_PID" ]; do
  SPIRE_PID=$(get_spire_pid)
  if [ -z "$SPIRE_PID" ]; then
    sleep 5
  fi
done

echo "Found spire-server process with PID: $SPIRE_PID"

# Global variables for spire access
SPIRE_SERVER_ROOT_PATH=""
SOCKET_PATH=""
SOCKET_FLAG=""

# Function to setup spire server path
setup_spire_access() {
  local new_pid=$(get_spire_pid)
  if [ -z "$new_pid" ]; then
    echo "ERROR: spire-server process not found"
    return 1
  fi
  
  SPIRE_PID="$new_pid"
  SPIRE_SERVER_ROOT_PATH="/proc/${SPIRE_PID}/root"
  
  # Verify the path exists
  if [ ! -d "$SPIRE_SERVER_ROOT_PATH" ]; then
    echo "ERROR: spire-server root path does not exist: $SPIRE_SERVER_ROOT_PATH"
    return 1
  fi
  
  SOCKET_PATH="${SPIRE_SERVER_ROOT_PATH}/tmp/spire-server/private/api.sock"
  SOCKET_FLAG="-socketPath ${SOCKET_PATH}"
  
  return 0
}

# Function to call spire-server (replaces alias)
spire_server() {
  "${SPIRE_SERVER_ROOT_PATH}/opt/spire/bin/spire-server" "$@"
}

# Initial setup
setup_spire_access

echo "Checking spire-server status"
while true; do
  # Check if current PID is still valid
  if ! is_pid_valid "$SPIRE_PID"; then
    echo "WARNING: spire-server PID $SPIRE_PID is no longer valid, waiting for new process..."
    SPIRE_PID=""
    while [ -z "$SPIRE_PID" ]; do
      SPIRE_PID=$(get_spire_pid)
      if [ -z "$SPIRE_PID" ]; then
        sleep 5
      fi
    done
    echo "Found new spire-server process with PID: $SPIRE_PID"
    if ! setup_spire_access; then
      echo "Failed to setup spire access, retrying..."
      sleep 5
      continue
    fi
  fi
  
  # Try to communicate with spire-server
  if spire_server entry show ${SOCKET_FLAG} &> /dev/null; then
    echo "Spire Server is up and responding"
    break
  fi
  
  echo "Waiting for spire-server to start..."
  sleep 5
done

echo "Spire Server is up, initializing cilium spire entries..."

AGENT_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/ns/{{ .Values.authentication.mutual.spire.install.namespace }}/sa/spire-agent"
AGENT_SELECTORS="-selector k8s_psat:agent_ns:{{ .Values.authentication.mutual.spire.install.namespace }} -selector k8s_psat:agent_sa:spire-agent"
CILIUM_AGENT_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/cilium-agent"
CILIUM_AGENT_SELECTORS="-selector k8s:ns:{{ include "cilium.namespace" . }} -selector k8s:sa:{{ .Values.serviceAccounts.cilium.name }}"
CILIUM_OPERATOR_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/cilium-operator"
CILIUM_OPERATOR_SELECTORS="-selector k8s:ns:{{ include "cilium.namespace" . }} -selector k8s:sa:{{ .Values.serviceAccounts.operator.name }}"
ZTUNNEL_SPIFFE_ID="spiffe://{{ .Values.authentication.mutual.spire.trustDomain }}/ztunnel"
ZTUNNEL_SELECTORS="-selector k8s:ns:{{ include "cilium.namespace" . }} -selector k8s:sa:ztunnel"

# Function to execute spire entry operations with retry on PID change
execute_spire_entry() {
  local max_retries=3
  local retry_count=0
  
  while [ $retry_count -lt $max_retries ]; do
    # Check if PID is still valid before executing
    if ! is_pid_valid "$SPIRE_PID"; then
      echo "WARNING: spire-server PID changed during operation, updating..."
      SPIRE_PID=""
      while [ -z "$SPIRE_PID" ]; do
        SPIRE_PID=$(get_spire_pid)
        if [ -z "$SPIRE_PID" ]; then
          sleep 5
        fi
      done
      if ! setup_spire_access; then
        echo "Failed to setup spire access, retrying..."
        retry_count=$((retry_count + 1))
        sleep 2
        continue
      fi
    fi
    
    # Execute the command - evaluate it to handle function calls
    if eval "$@"; then
      return 0
    else
      echo "Command failed, retrying... (attempt $((retry_count + 1))/$max_retries)"
      retry_count=$((retry_count + 1))
      sleep 2
    fi
  done
  
  return 1
}

while true; do
  # Verify PID is still valid before each iteration
  if ! is_pid_valid "$SPIRE_PID"; then
    echo "WARNING: spire-server process has terminated, waiting for restart..."
    SPIRE_PID=""
    while [ -z "$SPIRE_PID" ]; do
      SPIRE_PID=$(get_spire_pid)
      if [ -z "$SPIRE_PID" ]; then
        sleep 5
      fi
    done
    echo "Found new spire-server process with PID: $SPIRE_PID"
    if ! setup_spire_access; then
      echo "Failed to setup spire access, retrying in 5 seconds..."
      sleep 5
      continue
    fi
    
    # Wait for server to be ready after restart
    echo "Waiting for restarted spire-server to be ready..."
    while ! spire_server entry show ${SOCKET_FLAG} &> /dev/null; do
      if ! is_pid_valid "$SPIRE_PID"; then
        echo "PID changed again during readiness check, restarting wait loop..."
        break
      fi
      sleep 5
    done
    
    # If PID changed during readiness check, restart the main loop
    if ! is_pid_valid "$SPIRE_PID"; then
      continue
    fi
  fi

  echo "Ensuring agent entry"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $AGENT_SPIFFE_ID $AGENT_SELECTORS | grep -q "Found 0 entries"; then
    execute_spire_entry spire_server entry create ${SOCKET_FLAG} -spiffeID $AGENT_SPIFFE_ID $AGENT_SELECTORS -node
  fi

  echo "Ensuring cilium-agent entry (required for the delegated identity to work)"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $CILIUM_AGENT_SPIFFE_ID $CILIUM_AGENT_SELECTORS | grep -q "Found 0 entries"; then
    execute_spire_entry spire_server entry create ${SOCKET_FLAG} -spiffeID $CILIUM_AGENT_SPIFFE_ID -parentID $AGENT_SPIFFE_ID $CILIUM_AGENT_SELECTORS
  fi

  echo "Ensuring cilium-operator entry (required for creating SPIFFE identities)"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $CILIUM_OPERATOR_SPIFFE_ID $CILIUM_OPERATOR_SELECTORS | grep -q "Found 0 entries"; then
    execute_spire_entry spire_server entry create ${SOCKET_FLAG} -spiffeID $CILIUM_OPERATOR_SPIFFE_ID -parentID $AGENT_SPIFFE_ID $CILIUM_OPERATOR_SELECTORS
  fi

  echo "Ensuring ztunnel entry (required for ztunnel to get its identity)"
  if spire_server entry show ${SOCKET_FLAG} -spiffeID $ZTUNNEL_SPIFFE_ID $ZTUNNEL_SELECTORS | grep -q "Found 0 entries"; then
    execute_spire_entry spire_server entry create ${SOCKET_FLAG} -spiffeID $ZTUNNEL_SPIFFE_ID -parentID $AGENT_SPIFFE_ID $ZTUNNEL_SELECTORS
  fi

  echo "Cilium Spire entries are initialized successfully or already in-sync"
  sleep 30
done
