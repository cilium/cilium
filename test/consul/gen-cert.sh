#!/usr/bin/env bash

need_regen() {
	files="server.crt server.key server-ca.crt consul-client.crt consul-client.key consul-client-ca.crt cilium-consul.yaml"
	for file in $files; do
		if [ ! -f $file ]; then
			return -1
		fi
	done
	return 0
}

clean() {
	rm  -f server.crt server.key server-ca.crt consul-client.crt consul-client.key consul-client-ca.crt cilium-consul.yaml
	exit 0
}

gen() {
	need_regen
	cert_exist=$?
	openssl x509 -in server.crt -text -noout|grep -q "IP Address:$1"
	is_same_ip=$?
	if [ $cert_exist -eq 0 ]; then
		if [ $is_same_ip -eq 0 ]; then
			echo "Skipping certs creation: certs exist"
			exit 0
		fi
	fi

	if [ -z "$(which cfssl)" ]; then
		echo "Please install the cfssl utility and make sure you have it in your \$PATH"
		echo "You can install it in your \$GOPATH by running:"
		echo "go get -u github.com/cloudflare/cfssl/cmd/cfssl"
		exit -1
	fi

	if [ -z "$(which cfssljson)" ]; then
		echo "Please install the cfssljson utility and make sure you have it in your \$PATH"
		echo "You can install it in your \$GOPATH by running:"
		echo "go get -u github.com/cloudflare/cfssl/cmd/cfssljson"
		exit -1
	fi

	cd "${dir}"

	echo "generating CA certs ==="
	cfssl gencert -initca ca-csr.json | cfssljson -bare ca


	echo "generating consul server certs ==="
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -hostname="$1,localhost" -config=ca-config.json -profile=server server.json | cfssljson -bare server

	echo "generating consul client certs ==="
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -hostname="127.0.0.1,localhost"-config=ca-config.json -profile=client consul-client.json | cfssljson -bare consul-client

	mv consul-client.pem consul-client.crt
	mv consul-client-key.pem consul-client.key
	cp ca.pem consul-client-ca.crt

	mv server.pem server.crt
	mv server-key.pem server.key
	mv ca.pem server-ca.crt

	chmod +r server.key

	cat > cilium-consul.yaml <<EOF
---
cafile: '$dir/consul-client-ca.crt'
keyfile: '$dir/consul-client.key'
certfile: '$dir/consul-client.crt'
EOF

	rm *.csr ca-key.pem
}


dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $dir
"$@"
cd -
