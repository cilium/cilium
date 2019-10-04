#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

function cleanup {
  monitor_stop
  cilium policy delete --all 2> /dev/null || true
  docker rm -f client 2> /dev/null || true
}

function finish_test {
#  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

trap finish_test EXIT

CLIENT_LABEL="id.client"

cleanup
logs_clear

function proxy_init {
  log "beginning proxy_init"
  create_cilium_docker_network

  docker run -dt --net=cilium --name client -l id.client tgraf/netperf

  wait_for_docker_ipv6_addr client

  log "waiting for all 2 endpoints to get an identity"
  while [ `cilium endpoint list -o jsonpath='{range [*]}{.status.identity.id}{"\n"}{end}' | grep '^[0-9]' | grep -v '^5$' | wc -l` -ne 2 ] ; do
    log "waiting..."
    sleep 1
  done

  CLIENT_ID=$(docker inspect --format '{{ .Id }}' client)
  echo $CLIENT_ID:/cacert.pem
  docker cp cacert.pem $CLIENT_ID:/cacert.pem

  monitor_start
  log "finished proxy_init"
}

function policy_single_egress {
  cilium policy delete --all
  cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.client":""}},
    "egress": [{
        "toPorts": [{
            "ports": [{"port": "53", "protocol": "ANY"}],
            "rules": {
                "dns": [
                    {"matchName": "www.lyft.com"},
                    {"matchPattern": "*.lyft.com"}
                ]
            }
        }]
    },{
	"toFQDNs": [
	    {"matchName": "www.lyft.com"},
	    {"matchPattern": "*.lyft.com"}
        ],
	"toPorts": [{
	    "ports": [{"port": "443", "protocol": "tcp"}],
	    "terminatingTLS": {
	        "certificate": {
		    "Name": "-----BEGIN CERTIFICATE-----\nMIIEYTCCA0mgAwIBAgIJAILStmLgUUcVMA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp\nc2NvMQ0wCwYDVQQKDARMeWZ0MRkwFwYDVQQLDBBMeWZ0IEVuZ2luZWVyaW5nMRAw\nDgYDVQQDDAdUZXN0IENBMB4XDTE4MTIxNzIwMTgwMFoXDTIwMTIxNjIwMTgwMFow\ngaYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1T\nYW4gRnJhbmNpc2NvMQ0wCwYDVQQKDARMeWZ0MRkwFwYDVQQLDBBMeWZ0IEVuZ2lu\nZWVyaW5nMRowGAYDVQQDDBFUZXN0IEJhY2tlbmQgVGVhbTEkMCIGCSqGSIb3DQEJ\nARYVYmFja2VuZC10ZWFtQGx5ZnQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAuvPdQdmwZongPAgQho/Vipd3PZWrQ6BKxIb4l/RvqtVP321IUTLs\n4vVwpXoYJ+12L+XOO3jCInszs53tHjFpTI1GE8/sasmgR6LRr2krwSoVRHPqUoc9\ntzkDG1SzKP2TRTi1MTI3FO+TnLFahntO9Zstxhv1Epz5GZ/xQLE0/LLoRYzcynL/\niflk18iL1KM8i0Hy4cKjclOaUdnh2nh753iJfxCSb5wJfx4FH1qverYHHT6FopYR\nV40Cg0yYXcYo8yNwrg+EBY8QAT2JOMDokXNKbZpmVKiBlh0QYMX6BBiW249v3sYl\n3Ve+fZvCkle3W0xP0xJw8PdX0NRbvGOrBQIDAQABo4HAMIG9MAwGA1UdEwEB/wQC\nMAAwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATBB\nBgNVHREEOjA4hh5zcGlmZmU6Ly9seWZ0LmNvbS9iYWNrZW5kLXRlYW2CCGx5ZnQu\nY29tggx3d3cubHlmdC5jb20wHQYDVR0OBBYEFLHmMm0DV9jCHJSWVRwyPYpBw62r\nMB8GA1UdIwQYMBaAFBQz1vaSbPuePL++7GTMqLAMtk3kMA0GCSqGSIb3DQEBCwUA\nA4IBAQAwx3/M2o00W8GlQ3OT4y/hQGb5K2aytxx8QeSmJaaZTJbvaHhe0x3/fLgq\nuWrW3WEWFtwasilySjOrFOtB9UNmJmNOHSJD3Bslbv5htRaWnoFPCXdwZtVMdoTq\nIHIQqLoos/xj3kVD5sJSYySrveMeKaeUILTkb5ZubSivye1X2yiJLR7AtuwuiMio\nCdIOqhn6xJqYhT7z0IhdKpLNPk4w1tBZSKOXqzrXS4uoJgTC67hWslWWZ2VC6IvZ\nFmKuuGZamCCj6F1QF2IjMVM8evl84hEnN0ajdkA/QWnil9kcWvBm15Ho+oTvvJ7s\nM8MD3RDSq/90FSiME4vbyNEyTmj0\n-----END CERTIFICATE-----\n"		
		},
	        "privateKey": {
       		    "Name": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAuvPdQdmwZongPAgQho/Vipd3PZWrQ6BKxIb4l/RvqtVP321I\nUTLs4vVwpXoYJ+12L+XOO3jCInszs53tHjFpTI1GE8/sasmgR6LRr2krwSoVRHPq\nUoc9tzkDG1SzKP2TRTi1MTI3FO+TnLFahntO9Zstxhv1Epz5GZ/xQLE0/LLoRYzc\nynL/iflk18iL1KM8i0Hy4cKjclOaUdnh2nh753iJfxCSb5wJfx4FH1qverYHHT6F\nopYRV40Cg0yYXcYo8yNwrg+EBY8QAT2JOMDokXNKbZpmVKiBlh0QYMX6BBiW249v\n3sYl3Ve+fZvCkle3W0xP0xJw8PdX0NRbvGOrBQIDAQABAoIBAQCkPLR1sy47BokN\nc/BApn9sn5/LZH7ujBTjDce6hqzLIVZn6/OKEfj1cbWiSd6KxRv8/B/vMykpbZ5/\n/w9eZP4imEGmChWhwruh8zHOrdAYhEXmuwZxtgnLurQ2AHTcX9hPCYB0Va76H3ZI\nQ65JUm6NaeQOlGT6ExjrIA2rTYJFM84I1xH3XbDulS9S2FXNP9RIjV70HzvZw2LR\n1qSNfrnGAEbUCdrZT4BAYTGam5L061ofencYLAorr8K0eVWhUjGV9Jjpq8aG8zy5\nOy1070I0d7Iexfu7T1sQDIqpNkOtQxI8feQEKeKlRKYx6YEQ9vaVwBGa0SBVxQem\nE3YdXBnBAoGBAORlz8wlYqCx25htO/eLgr9hN+eKNhNTo4l905aZrG8SPinaHl15\nn+dQdzlJMVm/rh5+VE0NR0U/vzd3SrdnzczksuGFn0Us/Yg+zOl1+8+GFAtqw3js\nudFLKksChz4Rk/fZo2djtSiFS5aGBtw0Z9T7eorubkTSSfJ7IT99HIu5AoGBANGL\n0ff5U2LV/Y/opKP7xOlxSCVI617N5i0sYMJ9EUaWzvquidzM46T4fwlAeIvAtks7\nACO1cRPuWredZ/gEZ3RguZMxs6llwxwVCaQk/2vbOfATWmyqpGC9UBS/TpYVXbL5\nWUMsdBs4DdAFz8aCrrFBcDeCg4V4w+gHYkFV+LetAoGAB3Ny1fwaPZfPzCc0H51D\nhK7NPhZ6MSM3YJLkRjN5Np5nvMHK383J86fiW9IRdBYWvhPs+B6Ixq+Ps2WG4HjY\nc+i6FTVgvsb69mjmEm+w6VI8cSroeZdvcG59ULkiZFn6c8l71TGhhVLj5mM08hYb\nlQ0nMEUa/8/Ebc6qhQG13rECgYEAm8AZaP9hA22a8oQxG9HfIsSYo1331JemJp19\nrhHX7WfaoGlq/zsrWUt64R2SfA3ZcUGBcQlD61SXCTNuO+LKIq5iQQ4IRDjnNNBO\nQjtdvoVMIy2/YFXVqDIOe91WRCfNZWIA/vTjt/eKDLzFGv+3aPkCt7/CkkqZErWq\nSnXkUGECgYAvkemYu01V1WcJotvLKkVG68jwjMq7jURpbn8oQVlFR8zEh+2UipLB\nOmrNZjmdrhQe+4rzs9XCLE/EZsn7SsygwMyVhgCYzWc/SswADq7Wdbigpmrs+grW\nfg7yxbPGinTyraMd0x3Ty924LLscoJMWUBl7qGeQ2iUdnELmZgLN2Q==\n-----END RSA PRIVATE KEY-----\n"
		}
	    },
	    "originatingTLS": {
	        "trustedCA": {
       		    "Name": "-----BEGIN CERTIFICATE-----\nMIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\nADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\nb24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\nMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\nb3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\nca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\nIFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\nVOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\njgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\nA4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\nU5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\nN+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\no/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\nrqXRfboQnoZsG4q5WTP468SQvvG5\n-----END CERTIFICATE-----\n"
		}
	    },
	    "rules": {
                "HTTP": [{
		    "method": "GET",
		    "path": "/privacy"
                }]
	    }
	}]
    }]
}]
EOF
}

function proxy_test {
  log "beginning proxy test"
  monitor_clear

  log "trying to reach www.lyft.com IPv4 at http://www.lyft.com:443/privacy from client (expected: 200)"
  RETURN=$(docker exec -i client bash -c "curl -v --cacert /cacert.pem --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET https://www.lyft.com:443/privacy")
  if [[ "${RETURN//$'\n'}" != "200" ]]; then
    abort "GET /privacy, unexpected return ${RETURN//$'\n'} != 200"
  fi

  log "trying to reach www.lyft.com IPv4 at http://www.lyft.com:443/private from client (expected: 403)"
  RETURN=$(docker exec -i client bash -c "curl -v --cacert /cacert.pem --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET https://www.lyft.com:443/private")
  if [[ "${RETURN//$'\n'}" != "403" ]]; then
    abort "GET /private, unexpected return ${RETURN//$'\n'} != 403"
  fi

  log "finished proxy test"
}

proxy_init

policy_single_egress

cilium policy get

proxy_test

log "deleting all policies from Cilium"
cilium policy delete --all 2> /dev/null || true
log "removing containers"
docker rm -f client 2> /dev/null || true

test_succeeded "${TEST_NAME}"
