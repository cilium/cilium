#!/usr/bin/env bash

clean() {
	rm  -f server.crt server.key server-ca.crt consul-client.crt consul-client.key consul-client-ca.crt cilium-consul.yaml
	exit 0
}

gen_consul_config() {
	cat > cilium-consul.yaml <<EOF
---
cafile: '$dir/consul-client-ca.crt'
keyfile: '$dir/consul-client.key'
certfile: '$dir/consul-client.crt'
EOF
}

gen() {
	if [ -z "$(which cfssl)" ]; then
		echo "Please install the cfssl utility and make sure you have it in your \$PATH"
		echo "You can install it in your \$GOPATH by running:"
		echo "go install github.com/cloudflare/cfssl/cmd/cfssl@latest"
		exit -1
	fi

	if [ -z "$(which cfssljson)" ]; then
		echo "Please install the cfssljson utility and make sure you have it in your \$PATH"
		echo "You can install it in your \$GOPATH by running:"
		echo "go install github.com/cloudflare/cfssl/cmd/cfssljson@latest"
		exit -1
	fi

	cd "${dir}"

	echo "generating CA certs ==="
	cfssl gencert -initca ca-csr.json | cfssljson -bare ca


	echo "generating consul server certs ==="
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -hostname="$1,localhost,127.0.0.1" -config=ca-config.json -profile=server server.json | cfssljson -bare server

	echo "generating consul client certs ==="
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -hostname="localhost,127.0.0.1" -config=ca-config.json -profile=client consul-client.json | cfssljson -bare consul-client

	mv consul-client.pem consul-client.crt
	mv consul-client-key.pem consul-client.key
	cp ca.pem consul-client-ca.crt

	mv server.pem server.crt
	mv server-key.pem server.key
	mv ca.pem server-ca.crt
	rm *.csr ca-key.pem

	gen_consul_config
}


dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $dir
"$@"
cd -
