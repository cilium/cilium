#######################################
# Generate the certificate authority certificates in the form of ca-name.pem
# Arguments:
#   name
#######################################
generate_ca_certs(){
    if [ $# -ne 1 ]; then
        echo "Invalid arguments: usage generate_ca_certs <name>"
        exit
    fi
    name=${1}
    cat > ${name}-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "2191h"
    },
    "profiles": {
      "${name}": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "2191h"
      }
    }
  }
}
EOF

    cat > ca-${name}-csr.json <<EOF
{
  "CN": "${name}",
  "hosts": [
    "${name}"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "${name}",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert -initca ca-${name}-csr.json | cfssljson -bare ca-${name}

    openssl x509 -in ca-${name}.pem -text -noout
}

#######################################
# Generate server certificates in the form of cli-name.pem
# Arguments:
#   certificate-authority filename
#   server/client filename
#   server/client's hostname
#######################################
generate_server_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_client_certs <ca-name> <cli-name> <hostname>"
        exit
    fi
    ca_name=${1}
    cli_name=${2}
    master_hostname=${3}
    cat > ${cli_name}-csr.json <<EOF
{
  "CN": "${cli_name}",
  "hosts": [
    "${cli_name}",
    "${master_hostname}",
    "${master_ip}",
    "${cluster_api_server_ip}",
    "${cli_name}.cluster.default"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "${ca_name}",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${cli_name}-csr.json | cfssljson -bare ${cli_name}

    openssl x509 -in ${cli_name}.pem -text -noout
}

#######################################
# Generate kubelet client certificates in the form of "filename.pem"
# Arguments:
#   certificate-authority filename
#   client name
#   filename
#######################################
generate_kubelet_client_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_client_certs <ca-name> <cli-name> <filename>"
        exit
    fi
    ca_name=${1}
    cli_name=${2}
    filename=${3}
    cat > ${filename}-csr.json <<EOF
{
  "CN": "${cli_name}",
  "hosts": [
     "${cli_name}"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "system:nodes",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${filename}-csr.json | cfssljson -bare ${filename}

    openssl x509 -in ${filename}.pem -text -noout
}

#######################################
# Generate k8s component certificates in the form of "filename.pem"
# Arguments:
#   certificate-authority filename
#   k8s component name
#   filename
#######################################
generate_k8s_component_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_k8s_component_certs <ca-name> <k8s-component-name> <filename>"
        exit
    fi
    ca_name=${1}
    k8s_name=${2}
    cm_name=${3}
    cat > ${cm_name}-csr.json <<EOF
{
  "CN": "${k8s_name}",
  "hosts": [
     "${k8s_name}"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "${k8s_name}",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${cm_name}-csr.json | cfssljson -bare ${cm_name}

    openssl x509 -in ${cm_name}.pem -text -noout
}

#######################################
# Generates kubectl admin certificates in the form of "filename.pem"
# Arguments:
#   certificate-authority filename
#   username used in kubectl
#   filename
#######################################
generate_kubectl_admin_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_kubectl_admin_certs <ca-name> <username> <filename>"
        exit
    fi
    ca_name=${1}
    username=${2}
    filename=${3}
    cat > ${filename}-csr.json <<EOF
{
  "CN": "${username}",
  "hosts": [
     "${username}"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "system:masters",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${filename}-csr.json | cfssljson -bare ${filename}

    openssl x509 -in ${filename}.pem -text -noout
}

#######################################
# Generates etcd client certificates in the form of "filename.pem"
# Arguments:
#   certificate-authority filename
#   client name used in etcd
#   filename
#######################################
generate_etcd_client_certs() {
    if [ $# -ne 3 ]; then
        echo "Invalid arguments: usage generate_etcd_client_certs <ca-name> <client-name> <filename>"
        exit
    fi
    ca_name=${1}
    client_name=${2}
    filename=${3}
    cat > ${filename}-csr.json <<EOF
{
  "CN": "${client_name}",
  "hosts": [
    "${client_name}"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "San Francisco",
      "O": "kubernetes",
      "OU": "CI",
      "ST": "California"
    }
  ]
}
EOF

    cfssl gencert \
      -ca=ca-${ca_name}.pem \
      -ca-key=ca-${ca_name}-key.pem \
      -config=${ca_name}-config.json \
      -profile=${ca_name} \
      ${filename}-csr.json | cfssljson -bare ${filename}

    openssl x509 -in ${filename}.pem -text -noout
}
