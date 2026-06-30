## Intro

This package provides a basic echo server used by Gateway API conformance
tests. It is built into the `echo-basic` binary and is enabled by setting
`UDP_ECHO_SERVER` in the container environment, similar to `GRPC_ECHO_SERVER`
and `TCP_ECHO_SERVER`.

The server listens on UDP on the configured port (default `8080`, override
via `UDP_PORT`). For each datagram, it replies with a JSON envelope:

```json
{
  "request": "<original request body>",
  "namespace": "<NAMESPACE env var>",
  "ingress": "<INGRESS_NAME env var>",
  "service": "<SERVICE_NAME env var>",
  "pod": "<POD_NAME env var>"
}
```

The `namespace`, `ingress`, `service`, and `pod` fields mirror the pod context
populated by echo-basic for HTTP responses. They let tests with multiple
weighted backends distinguish replicas (for example, when validating weighted
UDP routing across distinct backend Services or Deployments). Any field is
returned as an empty string when its env var is unset.

## Container env vars

| Variable          | Required | Default | Description                                    |
| ----------------- | -------- | ------- | ---------------------------------------------- |
| `UDP_ECHO_SERVER` | yes      | _unset_ | When set, echo-basic runs the UDP echo server. |
| `UDP_PORT`        | no       | `8080`  | Port the UDP echo server listens on.           |
| `NAMESPACE`       | no       | empty   | Returned in the JSON envelope as `namespace`.  |
| `INGRESS_NAME`    | no       | empty   | Returned in the JSON envelope as `ingress`.    |
| `SERVICE_NAME`    | no       | empty   | Returned in the JSON envelope as `service`.    |
| `POD_NAME`        | no       | empty   | Returned in the JSON envelope as `pod`.        |

## Testing the image works

Determine your pod IP for the udpechoserver:

```
kubectl get po -o wide | grep 'udpechoserver'
```

Get a shell into a jump pod:

```
kubectl exec --stdin --tty shell-demo -- /bin/bash
```

Install netcat for UDP communication:

```
apt update
apt install netcat-traditional
```

Test the UDP echo (replace `192.168.55.24` with your own pod IP):

```
echo 'Hello World' | nc -u -w 1 192.168.55.24 8080
```

You should see a response like:

```
{"request":"Hello World\n","namespace":"default","ingress":"","service":"udp-echo","pod":"udp-echo-0"}
```
