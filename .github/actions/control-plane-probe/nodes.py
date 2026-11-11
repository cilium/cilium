#!/usr/bin/env python3
# Usage: nodes.py <pods.json> <events.json> <warnings file>
# Prints the pods and the Cilium readiness of each node, and the probe timeout bursts on it.
import json
import sys
from datetime import datetime, timedelta

BURST_WINDOW = timedelta(seconds=30)
BURST_PODS = 5


def ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def load(path):
    try:
        with open(path) as f:
            return json.load(f).get("items", [])
    except (OSError, ValueError):
        return []


pods, events = load(sys.argv[1]), load(sys.argv[2])
nodes = {}
for pod in pods:
    node = pod.get("spec", {}).get("nodeName")
    if not node:
        continue
    n = nodes.setdefault(node, {"pods": 0, "kube-system": 0, "cilium-ready": "-", "timeouts": []})
    n["pods"] += 1
    meta = pod["metadata"]
    if meta["namespace"] == "kube-system":
        n["kube-system"] += 1
        if meta.get("labels", {}).get("k8s-app") == "cilium":
            for cond in pod.get("status", {}).get("conditions", []):
                if cond.get("type") == "Ready" and cond.get("status") == "True":
                    n["cilium-ready"] = cond.get("lastTransitionTime", "-")

for ev in events:
    msg = ev.get("message") or ""
    if ev.get("reason") != "Unhealthy" or not any(s in msg for s in ("Client.Timeout", "deadline exceeded", "timed out")):
        continue
    node = (ev.get("source") or {}).get("host") or ev.get("reportingInstance")
    if node not in nodes:
        continue
    obj = ev["involvedObject"]
    pod = f'{obj.get("namespace")}/{obj.get("name")}'
    for when in {ev.get("firstTimestamp"), ev.get("lastTimestamp"), ev.get("eventTime")} - {None}:
        nodes[node]["timeouts"].append((ts(when), pod))

with open(sys.argv[3], "a") as warnings:
    for node in sorted(nodes, key=lambda k: nodes[k]["cilium-ready"]):
        n = nodes[node]
        hits = sorted(n["timeouts"])
        best, best_at = 0, None
        for i, (start, _) in enumerate(hits):
            window = {pod for when, pod in hits[i:] if when - start < BURST_WINDOW}
            if len(window) > best:
                best, best_at = len(window), start
        at = best_at.strftime("%Y-%m-%dT%H:%M:%SZ") if best_at else "-"
        print(f'node {node}: pods={n["pods"]} kube-system={n["kube-system"]} cilium-ready={n["cilium-ready"]} '
              f'probe-timeouts={len(hits)} max-pods-in-30s={best} at {at}')
        if best >= BURST_PODS:
            print(f"::warning::probes of {best} pods on node {node} timed out within 30s at {at}", file=warnings)
