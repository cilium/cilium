# ExternalAuth Test Service

This directory contains a minimal test auth service for Gateway API `ExternalAuth`
experiments with Cilium.

It exposes:

- HTTP ext_authz endpoint on port `8080`
- gRPC ext_authz endpoint on port `9000`

Both variants:

- always allow the request
- log one line per request
- add `X-Test-Authz` to the allow response

## Build

For a local `kind` cluster:

```bash
docker build -t external-authz-test:dev -f examples/kubernetes/gateway/external-authz/Dockerfile .
kind load docker-image external-authz-test:dev
```

## Deploy

This example assumes:

- Cilium Gateway API support is enabled
- Gateway API CRDs with `ExternalAuth` support are installed

Apply the full setup:

```bash
kubectl apply -f examples/kubernetes/gateway/external-authz/manifests.yaml
```

This creates:

- `auth-service` with HTTP and gRPC ext_authz endpoints
- an `echo` backend service
- one `Gateway`
- five `HTTPRoute`s:
  - `/http-auth` uses HTTP `ExternalAuth`
  - `/http-auth-shared` reuses the same HTTP `ExternalAuth` config on another path
  - `/http-auth-variant` reuses the same auth service with different HTTP auth settings
  - `/grpc-auth` uses gRPC `ExternalAuth`
  - `/no-auth` has no auth filter

## Verify

Get the gateway address:

```bash
kubectl -n gateway-external-authz-demo get gateway ext-authz-gateway
```

Then send requests:

```bash
curl -i http://GATEWAY_ADDRESS/http-auth
curl -i http://GATEWAY_ADDRESS/http-auth-shared
curl -i -H 'X-Debug-Token: demo' http://GATEWAY_ADDRESS/http-auth-variant
curl -i http://GATEWAY_ADDRESS/grpc-auth
curl -i http://GATEWAY_ADDRESS/no-auth
```

Watch auth logs:

```bash
kubectl -n gateway-external-authz-demo logs deploy/ext-authz-test -f
```

Expected behavior:

- `/http-auth` logs an HTTP auth request
- `/http-auth-shared` also logs an HTTP auth request through the same auth service
- `/http-auth-variant` logs an HTTP auth request to a different auth path (`/variant-check`)
- `/grpc-auth` logs a gRPC auth request
- `/no-auth` reaches the backend without an auth-service log line
