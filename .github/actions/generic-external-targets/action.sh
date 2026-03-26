#!/usr/bin/env bash

set -eu -o pipefail

TARGETNAME=nginx.external.svc.cluster.local
OTHERTARGETNAME=nginx.external-other.svc.cluster.local

# Create a private key for the self signed CA
openssl genrsa 2048 > ca-key.pem

# Create a self signed CA certificate
openssl req -new -x509 -nodes -days 365 \
    -key ca-key.pem \
    -subj "/O=Cilium/CN=Cilium CA" \
    -out ca-cert.pem

# Create a secret with the CA certificate, will be used by L7 tests as trused CA for
# connections between Envoy and our external services
kubectl create ns external-target-secrets
kubectl -n external-target-secrets create secret generic custom-ca --from-file=ca.crt=ca-cert.pem

# Create a cerificate signing request and private key for external services
# Note only the primary external target is in the common name.
openssl req -newkey rsa:2048 -nodes \
    -keyout external-service.cilium.key \
    -subj "/CN=$TARGETNAME" \
    -out external-service.cilium.req.pem

# Figure out the addresses of the external nodes.
mapfile -d ' ' -t IPTARGET < <(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
mapfile -d ' ' -t IPOTHERTARGET < <(kubectl get nodes -o jsonpath='{.items[1].status.addresses[?(@.type=="InternalIP")].address}')

# Create a config file to tell openssl how to turn the signing request into a certificate
# Make sure the key usage is such that we can use the cert for HTTPS traffic.
# Also make sure both domain names are in the subjectAltName so the certificate works for
# both external services and the IP addresses without domain name.
(IFS=''
cat > v3.ext << EOF
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage               = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign
subjectAltName         = DNS:$OTHERTARGETNAME, DNS:$TARGETNAME, DNS:fake.external.first.target, DNS:fake.external.second.target${IPTARGET[*]/#/, IP:}${IPOTHERTARGET[*]/#/, IP:}
EOF
)

# Turn the certificate signing request into a certificate, signed by our CA
openssl x509 -req -days 365 -set_serial 01 \
    -in external-service.cilium.req.pem \
    -out external-service.cilium.crt \
    -extfile v3.ext \
    -CA ca-cert.pem \
    -CAkey ca-key.pem

# Start the external targets.
mapfile -t NODES_WITHOUT_CILIUM < <(kubectl get nodes -l cilium.io/no-schedule=true -o name | sed 's@^node/@@')

kubectl create ns external
NGINX_CERT_BASE64="$(base64 -w0 external-service.cilium.crt)" \
NGINX_KEY_BASE64="$(base64 -w0 external-service.cilium.key)" \
EXTERNAL_NODE="${NODES_WITHOUT_CILIUM[0]}" \
envsubst '$NGINX_CERT_BASE64 $NGINX_KEY_BASE64 $EXTERNAL_NODE' < "$(dirname "$0")/nginx-external.yaml" | kubectl -n external apply -f -

kubectl create ns external-other
NGINX_CERT_BASE64="$(base64 -w0 external-service.cilium.crt)" \
NGINX_KEY_BASE64="$(base64 -w0 external-service.cilium.key)" \
EXTERNAL_NODE="${NODES_WITHOUT_CILIUM[1]}" \
envsubst '$NGINX_CERT_BASE64 $NGINX_KEY_BASE64 $EXTERNAL_NODE' < "$(dirname "$0")/nginx-external.yaml" | kubectl -n external-other apply -f -

kubectl -n external rollout status daemonset nginx --timeout 60s
kubectl -n external-other rollout status daemonset nginx --timeout 60s

echo "ipv4_external_target=${IPTARGET[0]}" >> $GITHUB_OUTPUT
echo "ipv4_other_external_target=${IPOTHERTARGET[0]}" >> $GITHUB_OUTPUT
if [ "${#IPTARGET[@]}" -ge 2 ] && [ "${#IPOTHERTARGET[@]}" -ge 2 ]; then
	echo "ipv6_external_target=${IPTARGET[1]}" >> $GITHUB_OUTPUT
	echo "ipv6_other_external_target=${IPOTHERTARGET[1]}" >> $GITHUB_OUTPUT
fi
echo "external_target_name=$TARGETNAME" >> $GITHUB_OUTPUT
echo "other_external_target_name=$OTHERTARGETNAME" >> $GITHUB_OUTPUT
