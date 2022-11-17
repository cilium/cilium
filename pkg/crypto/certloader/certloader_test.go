// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testReloadDelay is the time we expect Watcher to take to reload the files
const testReloadDelay = watcherEventCoalesceWindow + 100*time.Millisecond

/* initial tls files */

var initialHubbleServerCA = []byte(
	`-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIQMUvUDie0mikTSp2IsrB4YjANBgkqhkiG9w0BAQsFADAe
MRwwGgYDVQQDExNodWJibGUtY2EuY2lsaXVtLmlvMB4XDTIwMTAwMTEzMjUzMVoX
DTIzMTAwMTEzMjUzMVowHjEcMBoGA1UEAxMTaHViYmxlLWNhLmNpbGl1bS5pbzCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTvo+CAC97XWht2cHg5BAmZ
mXwlhPcBJEUFsUs+S4TrOnsgm9rSv0OQISVZ+GyJ0bjIqmDu1FXIH/YrUPTjbslj
9/0xfxDRMLjGisF/yB+ydLjHJZ3JUpVr8hWPsiC4ykK3nZS8tW0/sezIBd9Cx517
RpKGF9qzxSim37qnu41sVF9X8KcKKB5jLGjmYMsDfWmUPPLxdJ2y3N5PAmD7Ejtc
1Acw+DS1GoxZdLv+ULdWLqtg97rxx9KCd/M5p4q3z8Zp1vgndOFWcpu1XkLH5ncl
JI1XxgU2LorGQZkkUUVsjqnuMqvld0q8PkFWIppR2D08R9/4zJCm2ysswCBC3s8C
AwEAAaNhMF8wDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRcvx1oKKu4r3uIZaD5
gfqRoH2MdDANBgkqhkiG9w0BAQsFAAOCAQEATef0QXzMWq2xzdkJkZksxnE0KNE8
laEXtpLfwOIi7JjMoXWthKEmr2aB5VILmiIzoimmfEclfbCfZCfIqXhWIo8Tf54c
Csind5H8L/cyZFWIiKt8KL2UnJtpbJUndFEvHpLAIksur6FGMjlUWDay7Aoky30y
jesErGj1HyfHJ/uFwExPPjISeOaLho8HlSs2GWVGVwdj0quwDZpO1RNsjzwY/9dZ
5aHOmj879VLHjgIXZ5wmB8cEi+j/QMsJUQcck4AnbwJOHg3QNo7N/ijeXCilBmfU
/SIbm68WynGdIBXcA9lE8spxRk0u8aZ2XxWqjXNgrgOCEFb4LwFRauhpgQ==
-----END CERTIFICATE-----
`)

var initialHubbleServerCertificate = []byte(
	`-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIQcQC04oxPJl7cotVaSezlzzANBgkqhkiG9w0BAQsFADAe
MRwwGgYDVQQDExNodWJibGUtY2EuY2lsaXVtLmlvMB4XDTIwMTAwMTEzMjUzMVoX
DTIzMTAwMTEzMjUzMVowKjEoMCYGA1UEAwwfKi5kZWZhdWx0Lmh1YmJsZS1ncnBj
LmNpbGl1bS5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANoPyQ2f
MblccWQGeX/zm3csfW5CJ90yYtJzlfJqJGKzMExqwQzuUSUhqvGdPwZdtxrAADkR
OiDYxpy0fRcWGrA+bfGu9wmrlBiKhJ0ebycvO6w0zusu/rwwo/ca4EQ4zWFwB7OJ
TXEahzAjwm3xtedCbnP959FB4eOnBs1FEhf9+V2sX1npxzzJDjNCcE9h0xP7j2YR
7YkfSHJnYAhrxzM45tNP+q4SpwJWzw//noc7+vxXrAanoIyZpD70N8x9tVNMkn1K
sjITc8lA3A5CqNhp+xp3sOeXeiPam34WYB1gpyn+QhDc7VKN9VDfLFi3H96OVheu
P5JenROsfL/NW+UCAwEAAaOBjTCBijAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU
XL8daCiruK97iGWg+YH6kaB9jHQwKgYDVR0RBCMwIYIfKi5kZWZhdWx0Lmh1YmJs
ZS1ncnBjLmNpbGl1bS5pbzANBgkqhkiG9w0BAQsFAAOCAQEAIvmiOl06OPPXRTfR
+1dIvGeiG3DbAq0CcOHUOiH28qjszfDus1g70Ras9Kpk3A0KN0P0s4rtD8ejlSNs
zrM9rcGijVyJ0ClZRfcLzfPUrJdtOFivIr2/VnRMGMl4YOG4k2z09x1oMUciQgug
T/oUyxwRNGIO49kYm5sZBzB2gQ6rhTBEmhvWmeTRZiHeejmiQ88/MIE6eeuCcj3/
zsOAvZgq3nhKmaYWcri2m8tD7pgeVjxZjNHEBEi/Eq1excoox0j3LoqGwrEjNEhk
ebvs0eE9KzEzzdgj2pYILBLrg3oIL08wBcPDa118ZSt1UswOd9MlObCOI26cBExg
Cv6FpA==
-----END CERTIFICATE-----
`)

var initialHubbleServerPrivkey = []byte(
	`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2g/JDZ8xuVxxZAZ5f/Obdyx9bkIn3TJi0nOV8mokYrMwTGrB
DO5RJSGq8Z0/Bl23GsAAORE6INjGnLR9FxYasD5t8a73CauUGIqEnR5vJy87rDTO
6y7+vDCj9xrgRDjNYXAHs4lNcRqHMCPCbfG150Juc/3n0UHh46cGzUUSF/35Xaxf
WenHPMkOM0JwT2HTE/uPZhHtiR9IcmdgCGvHMzjm00/6rhKnAlbPD/+ehzv6/Fes
BqegjJmkPvQ3zH21U0ySfUqyMhNzyUDcDkKo2Gn7Gnew55d6I9qbfhZgHWCnKf5C
ENztUo31UN8sWLcf3o5WF64/kl6dE6x8v81b5QIDAQABAoIBABrO3//Nt3Y7WDFc
3mkNkOpYzN7WQUJfZGjNDv0rcWe08dYjNbKaRd2TwwlLNKlash0Wx7A8XvIU1G4F
fm9tJ0DNnASfZv2IW3+c3+rVCANAOkzUfS/KqkSGklHZuwKIHS/Cbx/yXFPwV/hi
HRAZLCzPLPcTmwFN4TB0o1BvEmdidrVAbR4BYo4sR/JHGKys55puz8UiuPjHt+ut
tgNFExLdkgxJHYrSlPVhDKkAzoQUvEGUp8FuPE87/Y1W8gEf706GnAoeOubksR1a
xLXmyYo4/MRR0PKiQ1bsFoclXKCcP53yRfSwJthm9WcOmsLBPfAmLX5p0AVlevV7
KnY+NCECgYEA9oCotdd9FlKQdwAK24I1twqhgYoluH1Nu3pkarDgG/5ZpPFYooJe
HA2fE4f6RrrAN3mMItUylXPYhBi1PyQLUZnS6ef8qj7cA89B+5p/TP0UkhFkM1ZB
V6Ir+v9Ztas6bcVBevCitfBHk6AlJBWG+ZMgc3kfQ72IUkSGa7ia9lkCgYEA4naa
ixah7QNLrspEe5y7HRsp4P8UlosdDeS8lvF0RcFaw55xK3++FPMxO8y7fA5XmDmn
r0FYIzrOYch/fhrdlHt80WOiU2iRxQBSgLqSGH8T/R9c2OcOErWOC3AHf/coWIaE
KQ2rDywz1P8MZTBYo5DJkD5OeC/J/AsqQy+HOG0CgYB1PSgApKbHsSkokAqZ8Eof
7px2AgCCyIXp/wI3hDxy0/xK6MbhM+QSr5/TKD8u2K+HMvYlswTF9D0sRpwdlcUU
YHbh7QZM6my2GyMkyYx2T4AzILZpfELDrUwBquU99FxrzP+hu0WIBunkGqzPhrWV
ihZLFXZ7P2/QwOq13S1GsQKBgAYb/P9TlPq35ArLGh3blJCscuzG9N860YXWbeAE
k4ZuOOyeEZ+CyrX1+ZYLZ+No36QTqhpoQOByba7locrdHq0qx6s+bNqjL4uI/rDK
V7ahdwCVIAQZ9585lqNoWktxd30r49TXsY2vO5a7arIwI7QF6+ogRC2p3GEYTAOT
/KnhAoGBAOZwZWOyvILbV6KwPdIXlsUwVamRqTWcclSHhDBpRFnDMHvEjgX+n2ip
04ilyqZt/3GLPVviBFOIeyvJEOCuHfxXxUZJOSu3JE+8e4YS30DfVxKSOBtwnzoE
1LgihmbI2xDcUKTrm7UBF2PeNA4MGk9ZpphzbGV18Hxpiov2ulhl
-----END RSA PRIVATE KEY-----
`)

var initialRelayClientCA = initialHubbleServerCA

var initialRelayClientCertificate = []byte(
	`-----BEGIN CERTIFICATE-----
MIIDUzCCAjugAwIBAgIRALW5Aia05bOKS5c6pCiF6vEwDQYJKoZIhvcNAQELBQAw
HjEcMBoGA1UEAxMTaHViYmxlLWNhLmNpbGl1bS5pbzAeFw0yMDEwMDExMzI1MzJa
Fw0yMzEwMDExMzI1MzJaMCMxITAfBgNVBAMMGCouaHViYmxlLXJlbGF5LmNpbGl1
bS5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKmhlb+yXgWK3dyq
0AyA2ZLHmH1D8Q+weeE2pNpSS9Nf3Q9/ILtQ149E4FnTh2FKrVspPo0n8AVJykev
HK3KQWQkzO/wirCaJiOEDXyB8mZuug4avJ0s/Kmde4urxp39iFUaJsAoujAwkuXZ
3dpNAGRjYRu92xUyBwjHYGSGzwKjonYGnGZJ9MfRT10W77taF7MC8ol2UpZi+VqG
uUsaD8kNDtNGpUYmFQIGdNJQz6ZHc8shQRYVtZgZ52oIy3HjfVpjM4reVjzvSaQs
+LvJKNinTP15tYiHzDFmPLQkM0I+xoXWi4kz7LZ62kn547A+yMsxd7Yqa9dufppC
PbKN4WECAwEAAaOBhjCBgzAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUXL8daCir
uK97iGWg+YH6kaB9jHQwIwYDVR0RBBwwGoIYKi5odWJibGUtcmVsYXkuY2lsaXVt
LmlvMA0GCSqGSIb3DQEBCwUAA4IBAQB9j/tj3OO6sbkkPWPMijC0KqSFl0RtGVfl
fFEqalxs+CAchrjgFz87rpe0omYdgUKGKp2RVxzt2ibVBo1z1JliZNVz6fNLiqT/
D+/4yGdQBtqJ+Z3PvZz1HNAls/+01d8hKpw4i5krRztlVWO8ubijjkgcHwtxSRL9
Y5AAszQL1crOr5upHAHV2JdhdYV16V+eAqBVXScI0f4LZA5jJfz+032rQh7YgV7m
fWreTeQPP1XlzwAgYXQ/hoWIsl3/qt0oP0N5s9IAGxZEe8cnSKPS2jc+Egz5f6zF
jjx7jgWrWRTL+F4ZJ9G6Qku0hFwVRTbR0i+2Gm4nxfx1yx/Cxd44
-----END CERTIFICATE-----
`)

var initialRelayClientPrivkey = []byte(
	`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqaGVv7JeBYrd3KrQDIDZkseYfUPxD7B54Tak2lJL01/dD38g
u1DXj0TgWdOHYUqtWyk+jSfwBUnKR68crcpBZCTM7/CKsJomI4QNfIHyZm66Dhq8
nSz8qZ17i6vGnf2IVRomwCi6MDCS5dnd2k0AZGNhG73bFTIHCMdgZIbPAqOidgac
Zkn0x9FPXRbvu1oXswLyiXZSlmL5Woa5SxoPyQ0O00alRiYVAgZ00lDPpkdzyyFB
FhW1mBnnagjLceN9WmMzit5WPO9JpCz4u8ko2KdM/Xm1iIfMMWY8tCQzQj7GhdaL
iTPstnraSfnjsD7IyzF3tipr125+mkI9so3hYQIDAQABAoIBABlu0qb1NUebdHw7
WAon33c0WdaeMyxpBz0PFlRtdlTw0JIcO2oaStd+Oiz9nBSoP6mlW22KiWAhmiR5
StF7u6YqJlfrNsAXvJQinmsGiLN28ope09y0/ATqSbW9QYA6nRA1ZY32DURgZAX2
Tl8GoIJsrAiexJQ+9fMJAZjQ5YS9iYTQUmom2JqudrpzgFWJnhTt4Et2JhbonRyB
RFrsGTBX1qD2ueW/U8pWdrLPml/vzNJNvwsPdw0rZe5tJAuYJXfStqyVT6Fd6Hb4
7Yu2pPdREEtNT1khY45ajRs4hg8LXOh6WVDaY5utSLt6Q3HdCHpwj9u8NwUQ/b0F
mlBvdwkCgYEA0/fPsSEVP22U2JLp6CPIPSO6pwDe+LC+VOsPlG+Ee18p+NRT8Whk
VxhiJ7nmWGNU2riqPlzcb8u2fP5RRcA59sPIu9htCln4t9E1mYYLpT3I8OJcPt6c
/YCoinR5rI5YpSw2hqAVGlfAI89JBOpFTj1ium17ON1Pgx2bLVfoND8CgYEAzN5a
/zcAAkYzDE/gJuGP/OI8v2JIASHBgkbCn8W9YuaahzPnvN5MTjRoggClu3sqim1t
pgE4zP+mSr6XNC4WgVOJknIyCIwPsH3xrcUiApcDDZJYbmteuhAX6C9dyraSSroY
BrP6sygL1QvIMKEsviZmn13xJYAI65gT7paGAl8CgYAnnFykljEZTEoPeszZQ66M
tluQD9qbELRQvCiKLZjNUUhPpqYVK9PsbrMRB21jQRS/VtkBlGrhPWlZzFC1vylV
0tp1OAmQcKXI/ACPMvyEIZqmYTapzQH7YYqdbQy70VIBc9SwrcOjy5gtWPQlRf4z
k8caXZE0XC8aqnKwM4hCEwKBgAdGMebz9f0ervtV7riSs8Ef61ZEUBgyMaPFjW2M
4N+dHomEb0sGfaEdPUS4byoMAoOtxQHq8zBcN3RZ9hZ1OHlZFP5tLZeeGYSDxEwO
PtnmsMYPlzI8f72NirvEysjC2MjseKPsSg+IcXscEvyfDG6oAGbSOBjDxg1Pdg23
rIRzAoGAYHc7ILNRbeD0bIH55JPQ7iu2DXNTW1KVhIkx2INPcbK7HgO2hHH52cEg
ck9YU3p58lvJC3iA/FwczkEgxt9h8EwJMdsNK1abzMNHUHu52udA6YZbrKs22OiT
whwz8ZXadaGGom3X1ZiHyCHnMvK26QUmUS0sa9t2RfSheawFpLo=
-----END RSA PRIVATE KEY-----
`)

/* rotated tls files */
var rotatedHubbleServerCA = []byte(
	`-----BEGIN CERTIFICATE-----
MIIDKDCCAhCgAwIBAgIRANiRi+O8t0+Pj0diEiMKmdgwDQYJKoZIhvcNAQELBQAw
HjEcMBoGA1UEAxMTaHViYmxlLWNhLmNpbGl1bS5pbzAeFw0yMDEwMDIxNDM0Mjha
Fw0yMzEwMDIxNDM0MjhaMB4xHDAaBgNVBAMTE2h1YmJsZS1jYS5jaWxpdW0uaW8w
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpM2E3ygbtAMhGlfmBgIXX
8Ag3pOGfiSzLKPljML9y3tlqJFgXp0jltkqHiVN6B4OTu4INNq8hs+HFjuSQIYYV
jWK/kOy6OeXDOtHgsPOmVYH0kx7H4ab1x/n53FyCVPys/6YucnrUczZ3qgT1W9VE
tX3nloDNnSVx/XLAxypeIGcc0Y499Th1wiYvIIgsEQYC06wXWLkSsUWfzwdSw6z6
8SZUWv7VKBUKzdS75lQ7HZH2ieXIGK5QJiOx/FWsEYg5qVAr9LRDnAc7+/Grhlzk
uendCX4tOCiJ7OqLbrUZWpczkRWNnU9ubEnKqoDpd+08uqQ2ukZAQUwM0Uyx9loj
AgMBAAGjYTBfMA4GA1UdDwEB/wQEAwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUTonq/wydKmZwQDgj
j4qGNm64msEwDQYJKoZIhvcNAQELBQADggEBAC69dVZpuqi3f0LwgMHa8txbugV3
cHo5qAWCkhkXgn042WpNMljt210eMTPWqngqYxG/48bGUwoFN727V+MVhpfsObJp
p+1F9RXaqBbz/tkMOn5y+cHN6BqOmayAqdni/37zGpd7uMlTSqzhoo65Kt2vlyp/
7kpam2+I7tBzPr0ecuYb199JFUQI6v7BjqRhZFj9hnBQ6CSLJqoC4nQ2ta3790VF
0ikZ9xbcDI8DaDA7GX1AVh7hWKMbXxiA7YomCv7O7WDnqj03CFGAOqdqjq388x5D
VJcWFKXxDGdcsZZEv9tqWWBsF5JLrPDMi27MIcsx2xHJJOitCxMKlPpsJT0=
-----END CERTIFICATE-----
`)

var rotatedHubbleServerCertificate = []byte(
	`-----BEGIN CERTIFICATE-----
MIIDYTCCAkmgAwIBAgIRAKUwf3+aawIR4auK2CHq5bswDQYJKoZIhvcNAQELBQAw
HjEcMBoGA1UEAxMTaHViYmxlLWNhLmNpbGl1bS5pbzAeFw0yMDEwMDIxNDM0Mjla
Fw0yMzEwMDIxNDM0MjlaMCoxKDAmBgNVBAMMHyouZGVmYXVsdC5odWJibGUtZ3Jw
Yy5jaWxpdW0uaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDNJ45j
sSUuFfOw4KY/Rp1a24X/6BbDTjZOYh3il3kCfUXn+kbP5RvGCV9hCJNve3zoeQXi
zugGM7UvsBnQo0UOa8Ua7uKR/A/FVwljF7A8gKMrkFURHi+TNUjvw+vCl+amZyKn
ks652EOsCCIgQfyrX78PzYXS+yfNwhOKjz4R3bH8iU7TWwtj3Sk/MtcWw12u8sUp
C7HrxCs99KeoJN0NQaQoDffhj21wPCvKUvEpQpDfey6WTS8LXrsx3RSAk8trduVn
ZDdvPJEVk5ln7BOzwiIupjbR5DY812Maj3MzndURC1gL3WIrlefO+Ff/NvM+msgO
EK9q/CCmE+rc8hrRAgMBAAGjgY0wgYowDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW
MBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaA
FE6J6v8MnSpmcEA4I4+KhjZuuJrBMCoGA1UdEQQjMCGCHyouZGVmYXVsdC5odWJi
bGUtZ3JwYy5jaWxpdW0uaW8wDQYJKoZIhvcNAQELBQADggEBAKciEXzgXotUmnH9
jEph8Lbt7K4Pymu3pvBT72WtF+KULvO5N8WdLsudJHlwThmu6K8eAdC1cJ0nh//k
TMcNzpq66iyYa/I7EnxNMbYpkRIX5dCZbrxYKWgtxlPpwy+ME9NYKV6ytF+DyYFB
WMUa1/E+6qLWtC56tpQ/tPJu1C1pLfRSYSEfVvmNhrGWslfPl9IoVBcGR9uOAgiP
o3K5hBEug4j6sbEK1W9U1UfigUgBQRR+cFiZNNW//x0Ok0xzc7EUQ934LGWHuveQ
AXxJydNWL7N1WmT8eXgARbsVxkYUEdUK/oIXNm4usjbg+BqxWvYwUgKdVHipn1fA
k1e/nZY=
-----END CERTIFICATE-----
`)

var rotatedHubbleServerPrivkey = []byte(
	`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAzSeOY7ElLhXzsOCmP0adWtuF/+gWw042TmId4pd5An1F5/pG
z+UbxglfYQiTb3t86HkF4s7oBjO1L7AZ0KNFDmvFGu7ikfwPxVcJYxewPICjK5BV
ER4vkzVI78Prwpfmpmcip5LOudhDrAgiIEH8q1+/D82F0vsnzcITio8+Ed2x/IlO
01sLY90pPzLXFsNdrvLFKQux68QrPfSnqCTdDUGkKA334Y9tcDwrylLxKUKQ33su
lk0vC167Md0UgJPLa3blZ2Q3bzyRFZOZZ+wTs8IiLqY20eQ2PNdjGo9zM53VEQtY
C91iK5XnzvhX/zbzPprIDhCvavwgphPq3PIa0QIDAQABAoIBABB0A69rHZg8mnat
Dag1eZk30d9cNbckJqbSp6Lskv/oHBsmr1ctALU5OzUFAw4F0Vazng06mtEkhHt2
nBtnfLpTWlN2pSUgGgOxn0cbNz8i8fMkeC4PRbGArIDOLbJFjHH8A4N8+qdc+NBr
NpFvuVvlKeWSjhEFo4OU9Qw/wLKd+Ey2cA1GZx29y9LvGLnI9lBnX1g1qk8F/pHX
qT8BVrFPAqIie18BGFhg/8TJRV6vLwWzUVlZcPltn1pNDFvb2YDrjwnyrmGiR7Bn
mP7hN8usFyMx1xqNUtmZwgIy5vrTajXppfboEiZE4bc4u4+CJg3NPiQ54wr42NY7
fD3kY6ECgYEA4Xey9erVniollM/UYRqBIQHs7+q7NnqAVJfDGT8WyM9IHOBPGIMc
DyXGPoSPbReVOvBbyxBcOrab2Dv9D9fKtQa8B3hTtAcUFcgtwWkS8lyWU3SlpKlb
Ca58ErEF+8LQeGG+7L6lojeDmbOdT94AYZirT3B/gFiGS2bKWWmSmgMCgYEA6O+p
sfUQtRvdTLQx3M9d5ben8IoNVvoEcVkhCmJOGAJ4XMCtdbORA24+MyCyRCssFWdp
FDJrlLoje1E6e3VXcCuYMKk7v5epx+6/ZR94j8NN9bn0YTz4vY7pXEx2tLnwkyvM
bNVNIQ6daS64Bce0i2qMTtn2I4kdMmsbeA5sSZsCgYB9zwXsFMp4A/qOa92NBXYS
TfnA8dDfGEHtcfVqa/qxuH/7pOpduiL5DNHu5pcFf4hEqAQAbjOYi3awlOCja3zv
wD9BR9Ik/WImuVlWt+PbmvBCxy76j4l+AH+5ClBVaCJdWeVoQwU3XBSxujjIbQ73
ZnII1LRAkKT3A/dbJv6nswKBgFjGZkUlYf20Je5CyrId8epHyWB6LMVWOfU9A8Oi
XaL25gprgHBYRE8rZ9cygd5LGdz6cWi6IpgnLLil54T/3pgodTMufE/zrEg/bIBM
szUPORoKieG5TA9qdPOxTJhqOQ7N5XYhAOk1WbapkIbbaqqrq9etaAp5CkCZ43ko
/go7AoGAacHr0EZIUReHo7wOJ5S38THwh9JTEQPTTM5VcPAYDT6e8EKu3kT8vmkl
6Bbq1o14gv76bhzez/ROIe/J/nt0E1eFVCdKp48UMCuCPk33iCdRnkf6HYhnkOte
bkgW+O6YI7Ruo6ai3on3cyX/Fxwpq2RuZPmlA39zmYXf3I+Jcm0=
-----END RSA PRIVATE KEY-----
`)

var rotatedRelayClientCA = rotatedHubbleServerCA

var rotatedRelayClientCertificate = []byte(
	`-----BEGIN CERTIFICATE-----
MIIDUjCCAjqgAwIBAgIQaZwuLNp1ORjiLV8uPMncpzANBgkqhkiG9w0BAQsFADAe
MRwwGgYDVQQDExNodWJibGUtY2EuY2lsaXVtLmlvMB4XDTIwMTAwMjE0MzQyOVoX
DTIzMTAwMjE0MzQyOVowIzEhMB8GA1UEAwwYKi5odWJibGUtcmVsYXkuY2lsaXVt
LmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApSg2j/kH+YXwLZDX
TyXl6Ax/zj61EVaHALjKUpFxd3iQmESNOusbdtqA4jvodFGC9ynxTC85h2mVKcsx
EmKPfljwvGk9w4Uz8Y/RD5HovbcllKXIPzy6eTPebRhnG1654nRaqM0b07uZs8/L
2bLhgDOdPsHA1IMArogHcuR/kX34l7Np4tkBYyWJ04eFNOsgIOmtT+SasEG981sv
VP+en8rHJkjJGduEnW8dMtOtUJVz7F6G5KXVGHMfZQHW7pC9mpvFI85W4vzAFj+G
30eqWe0cKWR8yJp8S+cCJp3H5oKifXkYerkOi0fFvJmrjuGipU4D9el2JmPHdKWh
vnSOawIDAQABo4GGMIGDMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBROier/DJ0q
ZnBAOCOPioY2briawTAjBgNVHREEHDAaghgqLmh1YmJsZS1yZWxheS5jaWxpdW0u
aW8wDQYJKoZIhvcNAQELBQADggEBAEixexJGASME7mXLQdDKuYhwcXRHisZ+7QQF
AoYKP1iOCKnXqW7zUvtHYcqPElJQxSEUqOTJGHHYBNPRw1m/ttziuc13D5fqMHx4
V71aw0DqkgE0MTVyMb3sa7KbeCYAKjVMxzEL9ex9LgVjeguweAxB6RFlXouad/j5
0rLO7aJ+kWoujFvMyHxvDOjzhy3QeHaNwEVaI4OXvcWJBT4kH8iRDwnW8Bvkl+xL
PC9VKuvBJYTYwMxFA1jPBEJWc79yXXOKgAV7s5r4H8M+xBX5Wsx4xAqZfnL4xo9M
wo5TVUwPz0/VOgPmIHMDFzfpzzUMMAxGRD26f9XPVhDQHmTzfto=
-----END CERTIFICATE-----
`)

var rotatedRelayClientPrivkey = []byte(
	`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEApSg2j/kH+YXwLZDXTyXl6Ax/zj61EVaHALjKUpFxd3iQmESN
OusbdtqA4jvodFGC9ynxTC85h2mVKcsxEmKPfljwvGk9w4Uz8Y/RD5HovbcllKXI
Pzy6eTPebRhnG1654nRaqM0b07uZs8/L2bLhgDOdPsHA1IMArogHcuR/kX34l7Np
4tkBYyWJ04eFNOsgIOmtT+SasEG981svVP+en8rHJkjJGduEnW8dMtOtUJVz7F6G
5KXVGHMfZQHW7pC9mpvFI85W4vzAFj+G30eqWe0cKWR8yJp8S+cCJp3H5oKifXkY
erkOi0fFvJmrjuGipU4D9el2JmPHdKWhvnSOawIDAQABAoIBAQCGrz2XuYlkVnLg
Zd8AH7LWwuKzCfZVdk/QKeJs5Uk4Ga0pT7Yw1yxlh5lVZW+S9CoucBjkfRqYMGVB
WP/is1e7vMJNlDGXMhiDJTpjTSUVGbde+rdLwrV7Q+5e32iuLFjAsQyB3gqUZ8fX
mFzwYu18xBq25ADiDRdQPYR9kJPrzBRsCbObSWsjzy/iEhrzwSR+8EjCy4yw7jxt
epGGKqL6xtRktWTvL86rOBbgo9rWQ72YIR4eckvm5Y3LIobIRZlYXpMfoMvC/KuN
6hR83bJyE4FX5DkyMK1xzab7gSJvRYdRPttW95vOaW/zD0vnKiQtvg8Gd3IrX/CU
/yyxxnYJAoGBANbxwrTJtf1OvnsGPpUl3Jp6j2nO+h37+oRx8bm+82QsrdoAMVsA
q3tuGyMCEyFeTk7M+kRicMjWatPg2EZMqEe2zvfGu/Azq5gH02u1XwdBWvts53aV
DmOkzv/CWD0lrBsZZV/DVzML32pm7QJc+xTOhDA8Ijq6mctqRM55xWY9AoGBAMSz
+qS9kRjVY5FBabwLkbVmkMtNvQmc/9LX6zlzBdGSPnIdpdeoMEzOBVvqrlGL52To
EGaM6mT++u61D8fsjtPehZeV6Pm/YC9PcqliC9sztgWb2MfOInSKjMVMtY+Aw0LC
5MglSw2unwhWIhPhNpyrWNUvIpQfYjb9s0k9oLnHAoGAMt8/XPiMqSo07PsaXsR6
RNmTDdDd47DapvQs6PBnvKLSdtEq3UX4UBtMMunvyyr9z6q15O+DkBUnbYQ+y8yi
225J59zSaFRiXXYktM5VcmsmdHFfCvLWWAEOuPuvVLGQ3U0ScCrUfZFmzFEV8UQ+
bLtAEAZ7d3joo3tAU7oAXWUCgYA2+gqqsqT0KOf8OCkiOqWN6s27VM3p+uxxdJG0
69YLffFgGbM5dDOTs91BlHUGK7EPveCfmPEGK1HdF9QCT7aXttDlzitgakGq12y3
tMSVjn1oUeej6JQuuG6h0k/IfPeWGDyzR+ETQOQIA3Lg1Yha/3UDmHn0plTgA8Zx
SP08DwKBgQDIKXVpTVtDG4LPzz6l+bJPDLwpP0RLkmRwaSKguPPmPD4o8C34fYlD
iovHbeDeZMzMtMS4gtmYNaMrlt8jKu2ZTEKozjOutd09jn5Q/6enTdn9J0NqDh7P
xALU7npUWpesQkvCSxmqOcnWHFD5FmeAmFD5DLHKYqo2Kg0x5BUw4g==
-----END RSA PRIVATE KEY-----
`)

type tlsConfigFiles struct {
	caFiles     []string
	certFile    string
	privkeyFile string
}

// directories create the TLS directories and return the TLS configuration file
// paths.
func directories(t *testing.T) (dir string, hubble, relay tlsConfigFiles) {
	dir = t.TempDir()

	// hubble tls config files
	hubbleDir := filepath.Join(dir, "hubble")
	hubble.caFiles = []string{filepath.Join(hubbleDir, "ca.crt")}
	hubble.certFile = filepath.Join(hubbleDir, "server.crt")
	hubble.privkeyFile = filepath.Join(hubbleDir, "server.key")
	if err := os.MkdirAll(hubbleDir, 0755); err != nil {
		t.Fatal("os.MkdirAll", err)
	}
	// relay tls config files
	relayDir := filepath.Join(dir, "relay")
	relay.caFiles = []string{filepath.Join(relayDir, "ca.crt")}
	relay.certFile = filepath.Join(relayDir, "server.crt")
	relay.privkeyFile = filepath.Join(relayDir, "server.key")
	if err := os.MkdirAll(relayDir, 0755); err != nil {
		t.Fatal("os.MkdirAll", err)
	}

	return
}

// setup create the TLS files with the initial TLS configurations.
func setup(t *testing.T, hubble, relay tlsConfigFiles) {
	// hubble tls config files
	if err := os.WriteFile(hubble.caFiles[0], initialHubbleServerCA, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(hubble.certFile, initialHubbleServerCertificate, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(hubble.privkeyFile, initialHubbleServerPrivkey, 0600); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	// relay tls config files
	if err := os.WriteFile(relay.caFiles[0], initialRelayClientCA, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(relay.certFile, initialRelayClientCertificate, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(relay.privkeyFile, initialRelayClientPrivkey, 0600); err != nil {
		t.Fatal("os.WriteFile", err)
	}
}

// rotate replace the TLS files with the rotated TLS configurations.
func rotate(t *testing.T, hubble, relay tlsConfigFiles) {
	// hubble tls config files
	if err := os.WriteFile(hubble.caFiles[0], rotatedHubbleServerCA, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(hubble.certFile, rotatedHubbleServerCertificate, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(hubble.privkeyFile, rotatedHubbleServerPrivkey, 0600); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	// relay tls config files
	if err := os.WriteFile(relay.caFiles[0], rotatedRelayClientCA, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(relay.certFile, rotatedRelayClientCertificate, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(relay.privkeyFile, rotatedRelayClientPrivkey, 0600); err != nil {
		t.Fatal("os.WriteFile", err)
	}
}

// k8sDataDirName creates a name for data dir in a similar fashion to Kubernetes
func k8sDataDirName() string {
	return time.Now().Format("..2006_01_02_15_04_05.000000000")
}

// k8sDirectories works like directories above, but simulates what Kubernetes
// would create for the following volume definition:
//
//	---
//	- name: hubble-tls
//	  projected:
//	    sources:
//	    - secret:
//	        items:
//	        - key: ca.crt
//	          path: client-ca.crt
//	        - key: tls.crt
//	          path: server.crt
//	        - key: tls.key
//	          path: server.key
//	        name: hubble-server-certs
//	        optional: true
func k8sDirectories(t *testing.T) (dir string, hubble tlsConfigFiles) {
	dir = t.TempDir()

	hubble.caFiles = []string{filepath.Join(dir, "client-ca.crt")}
	hubbleDir := filepath.Join(dir, "hubble")
	hubble.certFile = filepath.Join(hubbleDir, "server.crt")
	hubble.privkeyFile = filepath.Join(hubbleDir, "server.key")

	emptyDataDir := k8sDataDirName()
	dataDir := filepath.Join(dir, emptyDataDir)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal("os.MkdirAll", err)
	}
	if err := os.Symlink(emptyDataDir, filepath.Join(dir, "..data")); err != nil {
		t.Fatal("os.Symlink", err)
	}

	return dir, hubble
}

// k8sUpdate updates the dir with the provided certificates and keyfiles the
// same way Kubernetes would. Requires dir to be created by k8sDirectories.
func k8sUpdate(t *testing.T, dir string, hubbleServerCert, hubbleServerKey, hubbleCA []byte) {
	newDataDir := k8sDataDirName()
	oldDataDir, err := os.Readlink(filepath.Join(dir, "..data"))
	if err != nil {
		t.Fatal("os.Readlink", err)
	}

	// create new ..data directory structure
	dataDir := filepath.Join(dir, newDataDir)
	if err = os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal("os.MkdirAll", err)
	}
	if err = os.MkdirAll(filepath.Join(dataDir, "hubble"), 0755); err != nil {
		t.Fatal("os.MkdirAll", err)
	}

	// write initial TLS certificates into dataDir
	if err := os.WriteFile(filepath.Join(dataDir, "hubble", "server.crt"), hubbleServerCert, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "hubble", "server.key"), hubbleServerKey, 0600); err != nil {
		t.Fatal("os.WriteFile", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "client-ca.crt"), hubbleCA, 0644); err != nil {
		t.Fatal("os.WriteFile", err)
	}

	// create new '..data_tmp' symlink to point to newDataDir
	if err := os.Symlink(newDataDir, filepath.Join(dir, "..data_tmp")); err != nil {
		t.Fatal("os.Symlink", err)
	}
	// overwrite '..data' with '..data_tmp'
	if err := os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal("os.Rename", err)
	}
	// remove old setup data dir
	if err := os.RemoveAll(filepath.Join(dir, oldDataDir)); err != nil {
		t.Fatal("os.RemoveAll", err)
	}
}

// k8sSetup works like setup but emulates what Kubernetes would do. Requires
// dir to be set up by k8sDirectories
func k8Setup(t *testing.T, dir string) {
	k8sUpdate(t, dir, initialHubbleServerCertificate, initialHubbleServerPrivkey, initialHubbleServerCA)

	// create intital symlinks
	if err := os.Symlink("..data/hubble", filepath.Join(dir, "hubble")); err != nil {
		t.Fatal("os.Symlink", err)
	}
	if err := os.Symlink("..data/client-ca.crt", filepath.Join(dir, "client-ca.crt")); err != nil {
		t.Fatal("os.Symlink", err)
	}
}

// k8sRotate works like rotate but emulates what Kubernetes would do. Requires
// dir to be set up by k8Setup
func k8sRotate(t *testing.T, dir string) {
	k8sUpdate(t, dir, rotatedHubbleServerCertificate, rotatedHubbleServerPrivkey, rotatedHubbleServerCA)
}

// cleanup remove all the TLS files and directories created by setup().
func cleanup(dir string) {
	os.RemoveAll(dir)
}
