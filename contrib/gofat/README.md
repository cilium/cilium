# gofat - List size of golang dependencies

Based on https://github.com/jondot/fattyproject/blob/master/gofat and adjusted to work with go 1.11 (more or less)

## Example

        gofat

        3.3M
        importmap golang_org/x/net/http/httpguts=vendor/golang_org/x/net/http/httpguts
        2.9M
        1.6M
        importmap golang_org/x/net/dns/dnsmessage=vendor/golang_org/x/net/dns/dnsmessage
        1.4M
        1.2M
        1.1M
        948K
        920K
        importmap github.com/c9s/goprocinfo/linux=github.com/cilium/cilium/vendor/github.com/c9s/goprocinfo/linux
        912K
        importmap golang_org/x/crypto/chacha20poly1305=vendor/golang_org/x/crypto/chacha20poly1305
