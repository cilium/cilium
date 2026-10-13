#!/usr/bin/env bash
# Usage: probe.sh start [true] | probe.sh stop <gke|aks|eks> <cluster> <zone, resource group or region> [job status]
set -uo pipefail

pcap="control-plane-handshakes.pcap"
tcpdump_log="control-plane-handshakes.log"
tcpdump_pid="control-plane-handshakes.pid"
log="control-plane-probe.log"
summary="control-plane-probe-summary.txt"
pids="control-plane-probe.pids"
control_pod="control-plane-probe"
control_started="control-plane-probe.control"
control_image="quay.io/cilium/alpine-curl:v1.10.0@sha256:913e8c9f3d960dde03882defa0edd3a919d529c2eb167caa7f54194528bde364"
counter_names="TcpActiveOpens TcpAttemptFails TcpRetransSegs TcpExtTCPSynRetrans TcpExtPAWSActive TcpExtTCPTimeouts"

now() {
  date -u +%FT%T.%3NZ
}

endpoint() {
  local server
  server=$(kubectl config view --minify --output 'jsonpath={.clusters[0].cluster.server}')
  server=${server#*://}
  echo "${server%%/*}"
}

api_port() {
  local port=443
  [[ $1 == *:* ]] && port=${1##*:}
  echo "${port}"
}

resolve() {
  local host=${1%:*}
  if [[ ${host} =~ ^[0-9.]+$ ]]; then
    echo "${host}"
  else
    getent ahostsv4 "${host}" | awk '{ print $1 }' | sort -u | xargs
  fi
}

# Reads /proc/net/snmp and /proc/net/netstat on stdin.
counters() {
  awk -v names="${counter_names}" '
    {
      p = $1
      sub(/:$/, "", p)
      if (!(p in header)) {
        header[p] = $0
        next
      }
      n = split(header[p], h, " ")
      for (i = 2; i <= n; i++)
        value[p h[i]] = $i
      delete header[p]
    }
    END {
      n = split(names, want, " ")
      for (i = 1; i <= n; i++)
        printf " %s=%s", want[i], (want[i] in value ? value[want[i]] : "-")
    }'
}

local_counters() {
  cat /proc/net/snmp /proc/net/netstat | counters
}

install_tcpdump() {
  command -v tcpdump >/dev/null && return 0
  timeout 60 sudo apt-get install -y -qq tcpdump >/dev/null ||
    { timeout 60 sudo apt-get update -qq && timeout 60 sudo apt-get install -y -qq tcpdump >/dev/null; }
  command -v tcpdump >/dev/null
}

probe_egress() {
  local urls=(https://api.ipify.org https://checkip.amazonaws.com) i=0 url ts out rc body err
  body=$(mktemp)
  err=$(mktemp)
  while :; do
    url=${urls[i++ % ${#urls[@]}]}
    ts=$(now)
    out=$(curl -sS -o "${body}" --connect-timeout 5 --max-time 8 \
      -w 'connect=%{time_connect} lport=%{local_port} rip=%{remote_ip}' "${url}" 2>"${err}")
    rc=$?
    echo "${ts} egress rc=${rc} ip=$(tr -d '[:space:]' <"${body}" | head -c 45) ${out} url=${url} err=$(tr '\n' ' ' <"${err}")"
    : >"${body}"
    sleep 10
  done
}

probe_api() {
  local url="https://$1/version" ts out rc err
  err=$(mktemp)
  while :; do
    ts=$(now)
    out=$(curl -sSk -o /dev/null --connect-timeout 25 --max-time 30 \
      -w 'code=%{http_code} connect=%{time_connect} lport=%{local_port} rip=%{remote_ip}' "${url}" 2>"${err}")
    rc=$?
    echo "${ts} api rc=${rc} ${out} url=${url} err=$(tr '\n' ' ' <"${err}")"
    sleep 10
  done
}

# Samples the runner's sockets to the API server, with the SYN retransmits and the process of each SYN-SENT one.
probe_sockets() {
  local ip peers=()
  for ip in $1; do
    [[ ${#peers[@]} -gt 0 ]] && peers+=(or)
    peers+=(dst "${ip}:$2")
  done
  while :; do
    echo "$(now) sockets$(ss -HtanoOp "${peers[@]}" | awk '
      {
        state[$1]++
        if ($1 != "SYN-SENT")
          next
        port = $4
        sub(/.*:/, "", port)
        retrans = proc = "-"
        for (i = 6; i <= NF; i++)
          if ($i ~ /^timer:\(/) {
            split($i, t, ",")
            sub(/\).*/, "", t[3])
            retrans = t[3]
          } else if ($i ~ /^users:\(\("/) {
            proc = $i
            sub(/^users:\(\("/, "", proc)
            sub(/".*/, "", proc)
            gsub(/[^A-Za-z0-9_.-]/, "_", proc)
          }
        ports = ports (ports == "" ? "" : ",") port "/" retrans "/" proc
      }
      END {
        printf " estab=%d syn-sent=%d time-wait=%d", state["ESTAB"], state["SYN-SENT"], state["TIME-WAIT"]
        printf " other=%d syn-sent-ports=%s", NR - state["ESTAB"] - state["SYN-SENT"] - state["TIME-WAIT"], (ports == "" ? "-" : ports)
      }')$(local_counters)"
    sleep 10
  done
}

capture() {
  local ep ips port filter hosts="" srcs="" inner="" ip a b c d
  if [[ -s ${pids} ]]; then
    echo "The control-plane capture is already running"
    return
  fi
  ep=$(endpoint)
  if [[ -z ${ep} ]]; then
    echo "::warning::no API server in the kubeconfig, skipping the control-plane probes"
    return
  fi
  ips=$(resolve "${ep}")
  port=$(api_port "${ep}")
  echo "$(now) start endpoint=${ep} ips=${ips// /,}$(local_counters)" | tee -a "${log}"

  if [[ -z ${ips} ]]; then
    echo "::warning::${ep} does not resolve, skipping the control-plane capture"
  elif ! install_tcpdump; then
    echo "::warning::tcpdump could not be installed, skipping the control-plane capture"
  else
    for ip in ${ips}; do
      IFS=. read -r a b c d <<<"${ip}"
      hosts+="${hosts:+ or }host ${ip}"
      srcs+="${srcs:+ or }src host ${ip}"
      inner+="${inner:+ or }icmp[24:4] == $((a << 24 | b << 16 | c << 8 | d))"
    done
    filter="((${hosts}) and tcp port ${port} and (tcp[tcpflags] & (tcp-syn|tcp-rst|tcp-fin) != 0))"
    # Pure ACKs from the API server, to see a challenge ACK answer a SYN.
    filter+=" or ((${srcs}) and tcp src port ${port} and tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-push) == 0"
    filter+=" and ip[2:2] - ((ip[0]&0xf)<<2) - ((tcp[12]&0xf0)>>2) == 0)"
    # Unreachables quoting a packet to the API server.
    filter+=" or (icmp[icmptype] == icmp-unreach and (${inner}))"
    echo "Capturing ${filter}"
    # AppArmor denies tcpdump a runner-owned log file, so its output goes through a pipe.
    # shellcheck disable=SC2016
    sudo sh -c 'echo "$$" >"$1" && shift && exec tcpdump "$@"' sh "${tcpdump_pid}" \
      -i any -n -s 128 -U -Z root -w "${pcap}" "${filter}" </dev/null 2>&1 | cat >"${tcpdump_log}" 2>&1 &
  fi

  probe_egress </dev/null >>"${log}" 2>&1 &
  echo $! >"${pids}"
  probe_api "${ep}" </dev/null >>"${log}" 2>&1 &
  echo $! >>"${pids}"
  if [[ -n ${ips} ]]; then
    probe_sockets "${ips}" "${port}" </dev/null >>"${log}" 2>&1 &
    echo $! >>"${pids}"
  fi
}

# Connects to the same endpoint every 5s from a node without Cilium.
start_control() {
  local ep script overrides
  ep=$(endpoint)
  [[ -z ${ep} ]] && return
  # shellcheck disable=SC2016
  script='while :; do
    ts=$(date -u +%FT%TZ)
    out=$(curl -sk -o /dev/null --connect-timeout 30 --max-time 35 \
      -w "code=%{http_code} connect=%{time_connect} tls=%{time_appconnect} lport=%{local_port} rip=%{remote_ip}" "$1")
    rc=$?
    echo "${ts} incluster rc=${rc} ${out}"
    sleep 5
  done'
  overrides='{"apiVersion": "v1", "spec": {"hostNetwork": true, "nodeSelector": {"cilium.io/no-schedule": "true"}, "tolerations": [{"operator": "Exists"}]}}'
  if timeout 30 kubectl -n kube-system run "${control_pod}" --restart Never --image "${control_image}" \
    --overrides "${overrides}" --command -- sh -c "${script}" sh "https://${ep}/version"; then
    touch "${control_started}"
  else
    echo "::warning::could not start the in-cluster control-plane probe"
  fi
}

start() {
  capture
  [[ $1 == true ]] && start_control
}

authorized_networks() {
  case $1 in
  gke)
    timeout 60 gcloud container clusters describe "$2" --zone "$3" \
      --format 'value(masterAuthorizedNetworksConfig.cidrBlocks[].cidrBlock)'
    ;;
  aks)
    timeout 60 az aks show --resource-group "$3" --name "$2" \
      --query 'apiServerAccessProfile.authorizedIpRanges' --output tsv
    ;;
  eks)
    timeout 60 aws eks describe-cluster --region "$3" --name "$2" \
      --query 'cluster.resourcesVpcConfig.publicAccessCidrs' --output text
    ;;
  esac | tr ';,\t\n' '    ' | xargs
}

# Counts the handshakes in the capture, keyed by the runner's address and the SYN's sequence number.
handshakes() {
  tcpdump -tt -nn -S -r "${pcap}" 2>/dev/null | awk -v port="$1" -v warnings="$2" '
    function field(name, i) {
      for (i = 2; i < NF; i++)
        if ($i == name) {
          sub(/,$/, "", $(i + 1))
          return $(i + 1)
        }
      return ""
    }
    function finish(k) {
      flows++
      if (answered[k])
        hist[before[k]]++
      else
        unanswered++
      late_flows += (late[k] > 0)
      chack_flows += (chack[k] > 0)
    }
    / ICMP / {
      icmps++
      next
    }
    {
      for (i = 2; i < NF; i++)
        if ($i == ">")
          break
      src = $(i - 1)
      dst = $(i + 1)
      sub(/:$/, "", dst)
      flags = field("Flags")
      t = $1 + 0
      fromapi = src ~ ("\\." port "$")
      k = fromapi ? dst : src
      if (flags ~ /S/ && flags !~ /\./) {
        seq = field("seq")
        if (k in isn && isn[k] == seq) {
          if (t - tlast[k] < 0.2)
            next
          syns[k]++
          tlast[k] = t
          if (answered[k])
            late[k]++
          next
        }
        if (k in isn)
          finish(k)
        isn[k] = seq
        tlast[k] = t
        syns[k] = 1
        answered[k] = late[k] = chack[k] = 0
        next
      }
      if (!(k in isn) || answered[k])
        next
      if (flags ~ /S/) {
        if (field("ack") + 0 == (isn[k] + 1) % 4294967296) {
          answered[k] = 1
          before[k] = syns[k]
          if (syns[k] > maxsyns)
            maxsyns = syns[k]
        }
      } else if (fromapi && flags !~ /[RF]/)
        chack[k]++
    }
    END {
      for (k in isn)
        finish(k)
      printf "handshakes: %d, unanswered: %d, ICMP unreachable: %d\n", flows, unanswered, icmps
      printf "  answered on SYN:"
      for (i = 1; i <= maxsyns; i++)
        if (i in hist)
          printf " #%d=%d", i, hist[i]
      print ""
      if (late_flows)
        printf "::warning::the runner retransmitted the SYN of %d handshakes after their SYN-ACK reached its NIC\n", late_flows >> warnings
      if (chack_flows)
        printf "::warning::the API server ACKed %d handshakes before their SYN-ACK, as for a connection it still holds on that tuple\n", chack_flows >> warnings
    }
  '
}

summarize() {
  awk -v cidrs="$1" -v warnings="$2" -v names="${counter_names}" '
    function ip2n(ip, a) {
      split(ip, a, ".")
      return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]
    }
    function allowed(ip, i, c, p) {
      for (i = 1; i <= ncidrs; i++) {
        split(cidr[i], c, "/")
        p = 2 ^ (32 - (c[2] == "" ? 32 : c[2]))
        if (int(ip2n(ip) / p) == int(ip2n(c[1]) / p))
          return 1
      }
      return 0
    }
    function get(key, i) {
      for (i = 3; i <= NF; i++)
        if (index($i, key "=") == 1)
          return substr($i, length(key) + 2)
      return ""
    }
    BEGIN {
      ncidrs = split(cidrs, cidr, " ")
      ncounters = split(names, counter, " ")
    }
    $2 == "egress" {
      egresses++
      ip = get("ip")
      if (get("rc") + 0 != 0 || ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        egress_failed++
        next
      }
      if (!(ip in seen)) {
        order[++nips] = ip
        first[ip] = $1
      }
      seen[ip]++
      last[ip] = $1
      if (ncidrs && !allowed(ip))
        printf "::warning::runner egressed from %s at %s, outside the authorized networks %s\n", ip, $1, cidrs >> warnings
    }
    $2 == "api" {
      apis++
      if (get("rc") + 0 == 0 && get("connect") + 0 < 10)
        next
      if (!api_slow++)
        api_first = $1
    }
    $2 == "incluster" {
      controls++
      if (get("rc") + 0 != 0 || get("connect") + 0 >= 10)
        control_slow++
    }
    $2 == "sockets" {
      sockets++
      v = get("syn-sent") + 0
      if (v > synsent_max) {
        synsent_max = v
        synsent_max_at = $1
      }
      for (i = 1; i <= ncounters; i++) {
        v = get(counter[i])
        if (v !~ /^[0-9]+$/)
          continue
        if (!(counter[i] in c0))
          c0[counter[i]] = v
        c1[counter[i]] = v
      }
    }
    END {
      printf "egress IP samples: %d, failed: %d\n", egresses, egress_failed
      printf "  %-15s %6s  %-24s  %-24s  %s\n", "ip", "count", "first", "last", "authorized"
      for (i = 1; i <= nips; i++) {
        ip = order[i]
        printf "  %-15s %6d  %-24s  %-24s  %s\n", ip, seen[ip], first[ip], last[ip], (ncidrs ? (allowed(ip) ? "yes" : "NO") : "unknown")
      }
      printf "API samples: %d, connect >= 10s or failed: %d\n", apis, api_slow
      printf "API samples from a node without Cilium: %d, connect >= 10s or failed: %d\n", controls, control_slow
      printf "socket samples: %d, most SYN-SENT: %d at %s\n", sockets, synsent_max, (synsent_max_at == "" ? "-" : synsent_max_at)
      printf "runner counter deltas:"
      for (i = 1; i <= ncounters; i++)
        printf " %s=%d", counter[i], c1[counter[i]] - c0[counter[i]]
      print ""
      if (api_slow)
        printf "::warning::%d of %d API connects from the runner took 10s or more or failed, the first at %s\n", api_slow, apis, api_first >> warnings
      if (control_slow)
        printf "::warning::%d of %d API connects from a node without Cilium took 10s or more or failed\n", control_slow, controls >> warnings
      if (c1["TcpExtPAWSActive"] - c0["TcpExtPAWSActive"] > 0)
        printf "::warning::the runner rejected %d SYN-ACKs on their timestamps (TcpExtPAWSActive)\n", c1["TcpExtPAWSActive"] - c0["TcpExtPAWSActive"] >> warnings
    }
  ' "${log}"
}

# Appends the samples of the in-cluster probe to the log.
read_control() {
  local out where ok=""
  out=$(mktemp)
  for _ in 1 2; do
    timeout 20 kubectl -n kube-system logs "pod/${control_pod}" >"${out}" 2>&1 && ok=1 && break
  done
  if [[ -n ${ok} ]]; then
    grep ' incluster ' "${out}" >>"${log}"
    where=$(timeout 20 kubectl -n kube-system get pod "${control_pod}" \
      --output 'jsonpath={.status.phase} on {.spec.nodeName}' 2>&1)
    echo "read $(grep -c ' incluster ' "${out}") samples, ${where}"
  else
    echo "kubectl logs failed: $(head -c 300 "${out}" | tr '\n' ' ')"
  fi
}

stop() {
  local provider=$1 cluster=$2 location=$3 job_status=$4 ep cidrs="" warnings pid control="not started"
  if [[ ! -s ${pids} ]]; then
    echo "The control-plane probes are not running"
    return
  fi
  xargs kill <"${pids}" 2>/dev/null
  pid=$(cat "${tcpdump_pid}" 2>/dev/null)
  if [[ ${pid} =~ ^[0-9]+$ ]]; then
    sudo kill -INT "${pid}"
    for _ in $(seq 10); do
      sudo kill -0 "${pid}" 2>/dev/null || break
      sleep 1
    done
  fi
  cat "${tcpdump_log}" 2>/dev/null

  # After a cancellation, leave the remaining time to the cluster teardown.
  if [[ ${job_status} == cancelled ]]; then
    control="not read, the job was cancelled"
  else
    [[ -e ${control_started} ]] && control=$(read_control)
    cidrs=$(authorized_networks "${provider}" "${cluster}" "${location}")
  fi
  ep=$(endpoint)
  warnings=$(mktemp)
  {
    echo "date: $(now)"
    echo "endpoint: ${ep}, resolves to $(resolve "${ep}")"
    echo "authorized networks: ${cidrs:-unknown}"
    echo "in-cluster probe from a node without Cilium: ${control}"
    [[ -s ${pcap} ]] && handshakes "$(api_port "${ep}")" "${warnings}"
    summarize "${cidrs}" "${warnings}"
    echo "runner counters at stop:$(local_counters)"
    echo "== Azure IMDS network"
    curl -sS --noproxy '*' --max-time 3 -H Metadata:true \
      'http://169.254.169.254/metadata/instance/network?api-version=2021-02-01'
    echo
    echo "== sysctl"
    sysctl -a 2>/dev/null | grep -E '^net\.ipv4\.(tcp_syn|tcp_timestamps|tcp_tw_reuse|ip_local_port_range)'
  } >"${summary}" 2>&1
  cat "${summary}" "${warnings}"
}

case ${1:-} in
start)
  start "${2:-false}"
  ;;
stop)
  stop "${2:-}" "${3:-}" "${4:-}" "${5:-}"
  ;;
*)
  echo "usage: $0 start [true] | $0 stop <gke|aks|eks> <cluster> <location> [job status]" >&2
  exit 1
  ;;
esac
exit 0
