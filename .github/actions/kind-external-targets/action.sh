# Convert a number to an IPv4 address
function dec2ip {
    local ip delim dec=$@
    for e in {3..0}
    do
        ((octet = dec / (256 ** e) ))
        ((dec -= octet * 256 ** e))
        ip+=$delim$octet
        delim=.
    done
    echo "$ip"
}

# Convert a IPv4 address to a number
function ip2dec {
    local a b c d ip=$@
    IFS=. read -r a b c d <<< "$ip"
    echo "$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))"
}

# Get the CIDR mask from a CIDR
function cidrmask {
    local a b ip=$@
    IFS=/ read -r a b <<< "$ip"
    echo "$((b))"
}

# The the IP from a CIDR
function cidrip {
    local a b ip=$@
    IFS=/ read -r a b <<< "$ip"
    echo "$a"
}

# Return the number of IPs in a CIDR mask (works up to 63, since bash it limited to 64 bit signed integers)
function ipsinmask {
    local mask=$1
    local maxmask=$2
    echo "$((1<<$maxmask-$mask))"
}

# Count the amount of colons in an IPv6 address
function colcount {
    local ip=$1
    echo $(tr -dc ':' <<<$ip | wc -c)
}

# Fill the abbreviated zeros in an IPv6 address
function fillip6 {
    local ip=$1
    local zeros=$((9 - $(colcount $ip)))
    local zerostr
    for i in $(seq 1 $zeros)
    do
        zerostr="$zerostr:0"
    done
    echo $(sed -e "s/::/$zerostr/" <<<$ip)
}

# Offset an IPv6 address by a CIDR mask and a number of IPs
# Big ugly function to work on the individual 16-bit parts of the IPv6 address
function ip6offset {
    local ip=$1
    local addmask=$2
    local addips=${3:0}

    # Read the IPv6 address into 8 16-bit parts
    local a1 a2 b1 b2 c1 c2 d1 d2
    IFS=: read -r a1 a2 b1 b2 c1 c2 d1 d2 <<< "$ip"
    a1=$((16#$a1))
    a2=$((16#$a2))
    b1=$((16#$b1))
    b2=$((16#$b2))
    c1=$((16#$c1))
    c2=$((16#$c2))
    d1=$((16#$d1))
    d2=$((16#$d2))

    # Add the number of IPs to the last part of the address
    # We typically need to only add one or two, we don't handle overflows
    d2=$(($d2 + $addips))

    # The following series takes the mask, if the mask falls within the current 16-bit part:
    # Take 0xFFFF and shift it right by the mask amount, then add that to the current part
    # If the part overflows, we add 1 to the next part and subtract 0xFFFF from the current part
    # We repeat this for all 8 parts of the IPv6 address
    if [[ $addmask -gt 16 ]] ; then
        addmask=$(($addmask-16))
    else
        a1=$(($a1 + (16#ffff >> $addmask)))
        printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $a1 $a2 $b1 $b2 $c1 $c2 $d1 $d2
        return
    fi
    if [[ $addmask -gt 16 ]] ; then
        addmask=$(($addmask-16))
    else
        a2=$(($a2 + (16#ffff >> $addmask)))
        if [[ $a2 -gt 65535 ]] ; then
            a1=$(($a1+1))
            a2=$(($a2-65535))
        fi
        printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $a1 $a2 $b1 $b2 $c1 $c2 $d1 $d2
        return
    fi
    if [[ $addmask -gt 16 ]] ; then
        addmask=$(($addmask-16))
    else
        b1=$(($b1 + (16#ffff >> $addmask)))
        if [[ $b1 -gt 65535 ]] ; then
            a2=$(($a2+1))
            b1=$(($b1-65535))
        fi
        printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $a1 $a2 $b1 $b2 $c1 $c2 $d1 $d2
        return
    fi
    if [[ $addmask -gt 16 ]] ; then
        addmask=$(($addmask-16))
    else
        b2=$(($b2 + (16#ffff >> $addmask)))
        if [[ $b2 -gt 65535 ]] ; then
            b1=$(($b1+1))
            b2=$(($b2-65535))
        fi
        printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $a1 $a2 $b1 $b2 $c1 $c2 $d1 $d2
        return
    fi
    if [[ $addmask -gt 16 ]] ; then
        addmask=$(($addmask-16))
    else
        c1=$(($c1 + (16#ffff >> $addmask)))
        if [[ $c1 -gt 65535 ]] ; then
            b2=$(($b2+1))
            c1=$(($c1-65535))
        fi
        printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $a1 $a2 $b1 $b2 $c1 $c2 $d1 $d2
        return
    fi
    if [[ $addmask -gt 16 ]] ; then
        addmask=$(($addmask-16))
    else
        c2=$(($c2 + (16#ffff >> $addmask)))
        if [[ $c2 -gt 65535 ]] ; then
            c1=$(($c1+1))
            c2=$(($c2-65535))
        fi
        printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $a1 $a2 $b1 $b2 $c1 $c2 $d1 $d2
        return
    fi
    if [[ $addmask -gt 16 ]] ; then
        addmask=$(($addmask-16))
    else
        d1=$(($d1 + (16#ffff >> $addmask)))
        if [[ $d1 -gt 65535 ]] ; then
            c2=$(($c2+1))
            d1=$(($d1-65535))
        fi
        printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $a1 $a2 $b1 $b2 $c1 $c2 $d1 $d2
        return
    fi
    
    if [[ $addmask -gt 16 ]] ; then
        addmask=$(($addmask-16))
    else
        d2=$(($d2 + (16#ffff >> $addmask)))
        if [[ $d2 -gt 65535 ]] ; then
            d1=$(($d1+1))
            d2=$(($d2-65535))
        fi
        printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $a1 $a2 $b1 $b2 $c1 $c2 $d1 $d2
        return
    fi
    
    printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $a1 $a2 $b1 $b2 $c1 $c2 $d1 $d2
}

# Find the IPv4 and/or IPv6 ranges of the kind network
for subnet in $(docker network inspect kind | jq -r ".[0].IPAM.Config[].Subnet"); do
    if [[ $subnet =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ ]]; then
        IP4RANGE=$subnet
    elif [[ $subnet =~ ^[a-fA-F0-9:]+/ ]]; then
        IP6RANGE=$subnet
    fi
done

echo "IPv4 range: $IP4RANGE"
echo "IPv6 range: $IP6RANGE"

if [[ -n $IP4RANGE ]]; then
    IP4SUBMASK=$(($(cidrmask $IP4RANGE)+1))
    IP4SUBSTARTDEC=$(($(ip2dec $(cidrip $IP4RANGE)) + $(ipsinmask $IP4SUBMASK 32)))
    IP4TARGET=$(dec2ip $(($IP4SUBSTARTDEC + 1)))
    IP4OTHERTARGET=$(dec2ip $(($IP4SUBSTARTDEC + 2)))
    echo "ipv4_external_cidr=$(dec2ip $IP4SUBSTARTDEC)/$(($IP4SUBMASK))" >> $GITHUB_OUTPUT
    echo "ipv4_external_target=$IP4TARGET" >> $GITHUB_OUTPUT
    echo "ipv4_other_external_target=$IP4OTHERTARGET" >> $GITHUB_OUTPUT
fi

if [[ -n $IP6RANGE ]]; then
    IP6RANGESTART=$(fillip6 $(cidrip $IP6RANGE))
    IP6SUBRANGEMASK=$(($(cidrmask $IP6RANGE) + 1))
    IP6SUBRANGESTART=$(ip6offset $IP6RANGESTART $IP6SUBRANGEMASK 0)
    IP6TARGET=$(ip6offset $IP6SUBRANGESTART 128 1)
    IP6OTHERTARGET=$(ip6offset $IP6SUBRANGESTART 128 2)
    echo "ipv6_external_cidr=$IP6SUBRANGESTART/$IP6SUBRANGEMASK" >> $GITHUB_OUTPUT
    echo "ipv6_external_target=$IP6TARGET" >> $GITHUB_OUTPUT
    echo "ipv6_other_external_target=$IP6OTHERTARGET" >> $GITHUB_OUTPUT
fi

openssl genrsa 2048 > ca-key.pem

openssl req -new -x509 -nodes -days 365 \
    -key ca-key.pem \
    -subj "/O=Cilium/CN=Cilium CA" \
    -out ca-cert.pem

openssl req -newkey rsa:2048 -nodes \
    -keyout external-service.cilium.key \
    -subj "/CN=external-service.cilium" \
    -out external-service.cilium.req.pem

cat > v3.ext << EOF
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage               = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign
subjectAltName         = DNS:other-external-service.cilium, DNS:external-service.cilium
EOF

openssl x509 -req -days 365 -set_serial 01 \
    -in external-service.cilium.req.pem \
    -out external-service.cilium.crt \
    -extfile v3.ext \
    -CA ca-cert.pem \
    -CAkey ca-key.pem

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
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    server {
EOF

if [[ -n $IP4RANGE ]]; then
    echo "        listen              80;" >> nginx.conf
    echo "        listen              [::]:80;" >> nginx.conf
fi

if [[ -n $IP6RANGE ]]; then
    echo "        listen              443 ssl;" >> nginx.conf
    echo "        listen              [::]:443 ssl;" >> nginx.conf
fi

cat >> nginx.conf << EOF
        server_name         external-service.cilium;
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

IPFLAGS=""
if [[ -n $IP4TARGET ]]; then
    IPFLAGS="$IPFLAGS --ip $IP4TARGET"
fi
if [[ -n $IP6TARGET ]]; then
    IPFLAGS="$IPFLAGS --ip6 $IP6TARGET"
fi

# Create a webserver container in the same docker network as the kind cluster.
# So it would be like a non-k8s server in the same L3 network as the k8s cluster.
# And thus external for the purposes of the test, yet still has IPv6 connectivity inside the GHA runner.
CONTAINERID=$(docker run -d --name webserver --network kind \
    $IPFLAGS \
    -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro \
    -v $(pwd)/external-service.cilium.crt:/etc/ssl/external-service.cilium.crt:ro \
    -v $(pwd)/external-service.cilium.key:/etc/ssl/external-service.cilium.key:ro \
    nginx)
echo "Webserver container ID: $CONTAINERID"
docker logs webserver

IPFLAGS=""
if [[ -n $IP4OTHERTARGET ]]; then
    IPFLAGS="$IPFLAGS --ip $IP4OTHERTARGET"
fi
if [[ -n $IP6OTHERTARGET ]]; then
    IPFLAGS="$IPFLAGS --ip6 $IP6OTHERTARGET"
fi

CONTAINERID=$(docker run -d --name other-webserver --network kind \
    $IPFLAGS \
    -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro \
    -v $(pwd)/external-service.cilium.crt:/etc/ssl/external-service.cilium.crt:ro \
    -v $(pwd)/external-service.cilium.key:/etc/ssl/external-service.cilium.key:ro \
    nginx)
echo "Other webserver container ID: $CONTAINERID"
docker logs other-webserver

# Get the current CoreDNS config file
kubectl -n kube-system get configmap/coredns -o json | jq ".data.Corefile" -r  > Corefile

# Append custom DNS, add a fake domain 'external-service.cilium', and resolve it to our webserver
cat >> Corefile << EOF
cilium:53 {
    hosts {
EOF

if [[ -n $IP4TARGET ]]; then
    echo "        $IP4TARGET external-service.cilium" >> Corefile
fi
if [[ -n $IP6TARGET ]]; then
    echo "        $IP6TARGET external-service.cilium" >> Corefile
fi
if [[ -n $IP4OTHERTARGET ]]; then
    echo "        $IP4OTHERTARGET other-external-service.cilium" >> Corefile
fi
if [[ -n $IP6OTHERTARGET ]]; then
    echo "        $IP6OTHERTARGET other-external-service.cilium" >> Corefile
fi
cat >> Corefile << EOF
    }
}
EOF

# Turn the Corefile back into a JSON string
cat Corefile | jq -asR '.' > Corefile.json
# Create a patch for the CoreDNS configmap
echo "{}" | jq ".data.Corefile = $(cat Corefile.json)" - > patch.json
# Patch the CoreDNS configmap
kubectl -n kube-system patch configmap/coredns --patch-file patch.json
