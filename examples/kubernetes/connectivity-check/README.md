# Connectivity Checker App

Deploys a simple echo REST API with multiple replicas. Probe pods with multiple
replicas checks connectivity to echo pods with a ClusterIP service. Readiness
and liveness probe of probes will fail if connectivity to echo pods are
unhealthy.

```
$ kubectl create -f connectivity-check.yaml
$ kubectl get pods
NAME                    READY     STATUS    RESTARTS   AGE
echo-7d9f9564df-2hkhp   1/1       Running   0          37s
echo-7d9f9564df-jr87s   1/1       Running   0          37s
echo-7d9f9564df-lk6dl   1/1       Running   0          37s
echo-7d9f9564df-q5dpb   1/1       Running   0          37s
echo-7d9f9564df-zwhtw   1/1       Running   0          37s
probe-8689f6579-899hc   1/1       Running   0          37s
probe-8689f6579-9wzz7   1/1       Running   0          37s
probe-8689f6579-k8ggp   1/1       Running   0          37s
probe-8689f6579-sqdfb   1/1       Running   0          37s
probe-8689f6579-thv7j   1/1       Running   0          37s
```
