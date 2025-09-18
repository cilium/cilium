#!/usr/bin/env bash

LVH="$1"
KINDNETWORK="$2"
IP4TARGET="$3"
IP4OTHERTARGET="$4"
IP6TARGET="$5"
IP6OTHERTARGET="$6"

lvh_wrapper() {
	if [ "$LVH" = "true" ]; then
		ssh -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost "cd /host; ${@@Q}"
	else
		"$@"
	fi
}

TARGETNAME=fake.external.service.cilium
OTHERTARGETNAME=fake.external.service.other.cilium

echo "external_target_name=$TARGETNAME" >> $GITHUB_OUTPUT
echo "other_external_target_name=$OTHERTARGETNAME" >> $GITHUB_OUTPUT

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

# Create a config file to tell openssl how to turn the signing request into a certificate
# Make sure the key usage is such that we can use the cert for HTTPS traffic.
# Also make sure both domain names are in the subjectAltName so the certificate works for
# both external services and the IP addresses without domain name.
cat > v3.ext << EOF
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage               = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign
subjectAltName         = DNS:$OTHERTARGETNAME, DNS:$TARGETNAME, IP:$IP4TARGET, IP:$IP6TARGET, IP:$IP4OTHERTARGET, IP:$IP6OTHERTARGET
EOF

# Turn the certificate signing request into a certificate, signed by our CA
openssl x509 -req -days 365 -set_serial 01 \
    -in external-service.cilium.req.pem \
    -out external-service.cilium.crt \
    -extfile v3.ext \
    -CA ca-cert.pem \
    -CAkey ca-key.pem

# Create a nginx config file for our external services. Its very minimal, essentially just
# the default nginx config shipped with the container + config for SSL/TLS.
cat > nginx.conf << EOF
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;

    keepalive_timeout  65;

    server {
        listen              80;
        listen              [::]:80;
        listen              443 ssl;
        listen              [::]:443 ssl;
        server_name         $TARGETNAME;
        ssl_certificate     /etc/ssl/external-service.cilium.crt;
        ssl_certificate_key /etc/ssl/external-service.cilium.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;

        location / {
            root   /usr/share/nginx/html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   /usr/share/nginx/html;
        }
    }
}
EOF

# Start our first external target
CONTAINERID=$(lvh_wrapper docker run -d --name webserver --network $KINDNETWORK \
    --ip $IP4TARGET --ip6 $IP6TARGET \
    -v ./nginx.conf:/etc/nginx/nginx.conf:ro \
    -v ./external-service.cilium.crt:/etc/ssl/external-service.cilium.crt:ro \
    -v ./external-service.cilium.key:/etc/ssl/external-service.cilium.key:ro \
    nginx)

# Start the second external target
CONTAINERID=$(lvh_wrapper docker run -d --name other-webserver --network $KINDNETWORK \
    --ip $IP4OTHERTARGET --ip6 $IP6OTHERTARGET \
    -v ./nginx.conf:/etc/nginx/nginx.conf:ro \
    -v ./external-service.cilium.crt:/etc/ssl/external-service.cilium.crt:ro \
    -v ./external-service.cilium.key:/etc/ssl/external-service.cilium.key:ro \
    nginx)

# Get the current CoreDNS config file
kubectl -n kube-system get configmap/coredns -o json | jq ".data.Corefile" -r  > Corefile

# We use the fake `cilium` TLD. CoreDNS allows us to specify DNS config per TLD.
# Simply resolve our fake domains with a embedded hosts file.
cat >> Corefile << EOF
cilium:53 {
    hosts {
        $IP4TARGET $TARGETNAME
        $IP6TARGET $TARGETNAME
        $IP4OTHERTARGET $OTHERTARGETNAME
        $IP6OTHERTARGET $OTHERTARGETNAME
    }
}
EOF

# Turn the Corefile back into a JSON string
cat Corefile | jq -asR '.' > Corefile.json
# Create a patch for the CoreDNS configmap
echo "{}" | jq ".data.Corefile = $(cat Corefile.json)" - > patch.json
# Patch the CoreDNS configmap
kubectl -n kube-system patch configmap/coredns --patch-file patch.json

