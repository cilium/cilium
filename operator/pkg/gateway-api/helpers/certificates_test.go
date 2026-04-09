// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidPemFormat(t *testing.T) {
	cert := []byte(`-----BEGIN CERTIFICATE-----
MIIENDCCApygAwIBAgIRAKD/BLFBfwKIZ0WGrHtTH6gwDQYJKoZIhvcNAQELBQAw
dzEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMSYwJAYDVQQLDB10YW1t
YWNoQGZlZG9yYS5sYW4gKFRhbSBNYWNoKTEtMCsGA1UEAwwkbWtjZXJ0IHRhbW1h
Y2hAZmVkb3JhLmxhbiAoVGFtIE1hY2gpMB4XDTIzMDIyMTExMDg0M1oXDTI1MDUy
MTEyMDg0M1owUTEnMCUGA1UEChMebWtjZXJ0IGRldmVsb3BtZW50IGNlcnRpZmlj
YXRlMSYwJAYDVQQLDB10YW1tYWNoQGZlZG9yYS5sYW4gKFRhbSBNYWNoKTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIZy+0JRVjqpWgeq2dP+1oliO4A
CcZnMg4tSqPalhDQL6Mf68HYLfizyJIpRzMJ905rYd0AcmXmu/g0Eo8ykHxFDz5T
sePs2XQng8MN4azsRmm1l4f74ovawQzQcb822QP1CS6ILZ3VtwNjRh2nAwthYBMo
CkngDGeQ8Gl0tjHLFnBdTdSwQRmE2jtDBcAgyEGpq+6ReYt+/47nNn7dCftsVqhE
BYr9XH3itefHmsbfj7zWFbptdko7q9lMHwnBd+0hd40MmJIXMZrOGGFZjawJDBqS
sBq2Q3l6XQz8X7P/GA8Dn8h4w3rppmiaN7LOmGXeki3xX2wqnM+0s6aZYZsCAwEA
AaNhMF8wDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB8GA1Ud
IwQYMBaAFGQ2DB06CdQFQBsYPye0NBwErUNEMBcGA1UdEQQQMA6CDHVuaXR0ZXN0
LmNvbTANBgkqhkiG9w0BAQsFAAOCAYEArtHdKWXR6aELpfal17biabCPvIF9j6nw
uDzcdMYQLrXm8M+NHe8x3dpI7u3lltO+dzLng+nVKQOR3alQACSmRD9c7ie8eT5d
7zKOTk6keY195I1wVV4jbNLbNWa9y4RJQRTvBLAvAP9NVtUw2Q/w/ErUTqSyz+ob
dwnt4gYCw6dGnluLxlfF34DB9KflvVNSnkyMB/gsB4A3r1GPOIo0Gyf74ig3FWrS
wHYKnBbtZfYO0JV0LCoPyHe8g0XajZe8DCbP/E6SmlTNAmJESVjigTTcIBAkFI+n
toBAdxfhjKUGaClOHS29cpaiynjSayGm4RkHkx7mcAua9lWPf7pSa3mCcFb+wFr3
ABkHDPJH2acfaUK1vgKTgOwcG/6KA820/PraoSihLaPK/A7eg77r1EeYpt0Neppb
XjvUp3YmVlIMZXPzrjOsastoDSrsygj5jdVtm4Pslv9nPhzDrBjlZpEJScW4Jlb+
6wtd7p03UDBSKfTbVROVAe5mvJvA0hoS
-----END CERTIFICATE-----
`)
	key := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDCGcvtCUVY6qVo
HqtnT/taJYjuAAnGZzIOLUqj2pYQ0C+jH+vB2C34s8iSKUczCfdOa2HdAHJl5rv4
NBKPMpB8RQ8+U7Hj7Nl0J4PDDeGs7EZptZeH++KL2sEM0HG/NtkD9QkuiC2d1bcD
Y0YdpwMLYWATKApJ4AxnkPBpdLYxyxZwXU3UsEEZhNo7QwXAIMhBqavukXmLfv+O
5zZ+3Qn7bFaoRAWK/Vx94rXnx5rG34+81hW6bXZKO6vZTB8JwXftIXeNDJiSFzGa
zhhhWY2sCQwakrAatkN5el0M/F+z/xgPA5/IeMN66aZomjeyzphl3pIt8V9sKpzP
tLOmmWGbAgMBAAECggEAEjASoMJ2og9Ssn/1NbgT6G2N+Cc+wz2WPifWT6ZC2452
eEWcdMyJ+jz2dWOyzUCI0OtU/z10esH1KRvQBWUKjup1tDRpfd8KvUyalyNs2yRE
sNEYQuDCaLJ11nqNvgooqatDUf3msFx/Sqz5u/uTWHSmaQUeea+p2eaF8IvEKsQf
6QNklkeHsv+GVPv+iibfbXXne6I5aV35Rc4Q08zRCgYX/BN1AYXV6ho4RC9dZVGP
JUkSLzRadegok/EONKkrqLZOFJVb2wtFq85gJ01lODM/gj7GqM59M/wk55CaQIRD
9x5H4X4rpM2rhmiNLkIN0tGLKO8X31up7hTx9bvJcQKBgQD51MLWYYUPz/umvSrN
QOT9UhEHI/bxtCbWQthW3L1qrVT7DB8Jko/6/xYlXhl7nwVwJz24jJf9vuxWbBpL
HZRf0QsDO2/O4rqhKDov/GMUCx2shzc+J7k+T93KNVANYa05guqMeB8n30HProkF
LgihVFF20k9Z6SibUvgTMpF1EwKBgQDG5MBgc8oFXmlr/7pHKizC4F3eDAXUxVHM
WCIbSwMyzOXKqDcdXNDz8cQrjhKa2rD1fKhE0oRR+QvHz8IPC+0MsT7Q6QsIHYj5
CXubHr0s5k8PJAp+Lk2EdHePZQM/I/vj/gSwxnJ9Qs64FWZ25K9zYnNNsiojQel7
WVmI9IVaWQKBgD3BYggsQwANoV8uE455JCGaT6s8MKa+qXr9Owz9s7TS89a6wFFV
cVHSDF9gS1xLisSWbqNX3ZpTv4f9YOKAhVTKD7bU0maJlSiREREbikJCHSuwoO80
Uo4cn+6EDy2/n1pACkp+xvTMMzBrLGOjZW67sQd2JTdMc0Ux1TCpp1sRAoGAaEVI
rchGYyYp8pqw19o+eTQTQfPforqHta+GwfRDiwBsgCBMNLKSQTHAfG0RR+na1/gw
Z1ROVoNQL8K1pBnGft71ZaSnSeviAV19Vcd5ue5MCE4GyjwQG57Lh3uXhiShS9fC
McL4Br9djJh7jV06ti0o8dSzzqQhea9QB0LaHpECgYApc8oBoiK69s0wXyI4+Phx
ScBJ0XqDBYFkxyXr8Y5pEarEaqCtl1OPPMOiQRDWoxRR+FwA/0laSfh5xw0U3b+q
iZ2XpkrbQp034rC0UR6p+Km1Sv9AVCACAjrcQ3NZaf8bDOWqvpla7Auq0oG8i6UX
hEKCKf/N3gE1oMrTxVzUDQ==
-----END PRIVATE KEY-----
`)
	cacertBytes := []byte(`-----BEGIN CERTIFICATE-----
MIIFkTCCA3mgAwIBAgIUH3uq38eX9d6cECwygoJk9oNm0W0wDQYJKoZIhvcNAQEL
BQAwWDELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxHzAdBgNVBAoM
Fkt1YmVybmV0ZXMgR2F0ZXdheSBBUEkxEzARBgNVBAMMCmdhdGV3YXlhcGkwHhcN
MjYwMTA2MDYyNzU2WhcNMzYwMTA0MDYyNzU2WjBYMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKU29tZS1TdGF0ZTEfMB0GA1UECgwWS3ViZXJuZXRlcyBHYXRld2F5IEFQ
STETMBEGA1UEAwwKZ2F0ZXdheWFwaTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAIlfgZX1PSt38hlXg8FdMDbJEOvVRH3wUgbTOqYQnTN4ZYjYjc3bxdBl
V/JlfgaQJ0/x0wv0ewUfZbIw28HZ/FR3rTFrI7a/P79DUWwMe358nIthn1+P+pfu
7UMw1BeDfMn09k/k6Rt5QbSIeptvTNVIoKsp76Qgubb6Zr6aLE2FueBFBpVV4etw
0ks5/mY7RvQSrnDj1EBRQ6hgZ6CasXZEpsKQYYtOeKqjPZ+CD0TPyWCTP40Qu9v3
FVGjoCCk+Vg/x3grIOBBPgTzVGS6X6O1Pni/aIuqLDDX/CRv1rA64OfND6WzcLfb
8ZiR8ShGkQWQW8mqmoml1S8wfecum1NthXN+WfOqnUf9oO9oLiMCyuZpRgRO8XEq
5yXiKOkoYH4phbBkTY6b0ZN6sgKMtCFbKhWhQ+Ti+3638dYQP0+t4Y69qOjNzjke
0QK0mpFWUHZMdRoCQXhFUlMfBeHrbOJderVmkMHxW0QgZhaO9foRF37hVpIEIp4t
PNA719mDdBdXumJSuuo6k5kvElIMO15R7qN7UZuS3Pf1ebY9KeuDfvmiMoAfBQ7v
OAI32D4RNl6d4UkE3QPICeEIDli96PPJYl0nE9oszXbzm89T3BULpobzFWDicTzb
YqhsYEn1klVwYcB6pnkl6vmYj9qhbnAa4x79z+eeaa6+M//GL4WfAgMBAAGjUzBR
MB0GA1UdDgQWBBSmREz6QJfT6dz0gYFZsYXTPVpE9TAfBgNVHSMEGDAWgBSmREz6
QJfT6dz0gYFZsYXTPVpE9TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4ICAQBWh5KZcunnOuTsBJK3rS88WuyJcOjui5qmsPrfeSdijvzKBZ5Bj+/ypBGo
d7Yj0lJZ8a8wnuZZ3zf0wFlLUdH/tzuut/1gvu9BPaw/6mwVOYpFONPJ5H733wGp
0YH7uGxArWlHVFgUqds9FmUhTXGujBtLkr+mguvcu5PE6e7wEqSt5MMUi07omSBu
EvEpHdG+kmE8Paawn05fHTAvZZKbUrPtrRh4tqjh5i3qUI7E+ujHjMO7jGTD0yH9
DSf3/0bFUdjAXI2fk6KaLQXNmbsf98lP6vgckz0jU3QSCX8IPrzsnfrQ6QdIZkIe
XIchGtOwO+e1jIfVWMylOmbLUNQ/aVxS21/+k73Wc1hYbuPAlbro31bgq46jBiKU
RHCbCARsQ0Ficgc/t+FUkBQT4vI2wPjWGbLUr0txs75P6Rgk+tQudOZkO2jBh7Zj
5HYmXKfWVd8tilejFUHDj31VNLBEaCc+O1Glb4tm1ELpbFhkhIQ2Dbt0AzUuuw6w
uqNX5LRg2wdjEs43kgn7Ys111W2UOayH+PEcSwkZccBfO90dKM+2HWHYzyYUXkFi
7Z77jSKBcFC7NoTMrf+wTVBh84f4+GqIBz/eNsuVrkaPlizqd4wooI0fT5UOBK6S
9OfTOO6MMca9wAJDLKxMAKvbzUKLJlwHCrJgj38HwxNOUuiydw==
-----END CERTIFICATE-----`)
	keyAndCert := append(key, cert...)
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid cert pem",
			args: args{
				b: cert,
			},
			want: true,
		},
		{
			name: "value key pem",
			args: args{
				b: key,
			},
			want: true,
		},
		{
			name: "multiple valid pem blocks",
			args: args{
				b: keyAndCert,
			},
			want: true,
		},
		{
			name: "invalid first block",
			args: args{
				b: append([]byte("invalid block"), key...),
			},
			want: false,
		},
		{
			name: "invalid pem",
			args: args{
				b: []byte("invalid pem"),
			},
			want: false,
		},
		{
			name: "caCertBytes",
			args: args{
				b: cacertBytes,
			},
			want: true,
		},
		{
			name: "empty string",
			args: args{
				b: []byte(""),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, IsValidPemFormat(tt.args.b), "isValidPemFormat(%v)", tt.args.b)
		})
	}
}
