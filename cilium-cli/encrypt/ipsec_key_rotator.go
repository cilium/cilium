// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

var rotators = map[string]func(key ipsecKey) (ipsecKey, error){
	"":            func(key ipsecKey) (ipsecKey, error) { return key.rotate() },
	"gcm-aes":     newGcmAesKey,
	"hmac-sha256": newHmacSHA256Key,
	"hmac-sha512": newHmacSHA512Key,
}

func IsIPsecAlgoSupported(algo string) bool {
	_, ok := rotators[algo]
	return ok
}

func rotateIPsecKey(key ipsecKey, algo string) (ipsecKey, error) {
	return rotators[algo](key)
}

func newGcmAesKey(key ipsecKey) (ipsecKey, error) {
	authKey, err := generateRandomHex(40)
	if err != nil {
		return ipsecKey{}, err
	}
	newKey := ipsecKey{
		spi:       key.nextSPI(),
		spiSuffix: key.spiSuffix,
		algo:      "rfc4106(gcm(aes))",
		key:       authKey,
		size:      128,
	}
	return newKey, nil
}

func newHmacSHA256Key(key ipsecKey) (ipsecKey, error) {
	return newCbcAesKey(key, "hmac(sha256)", 32, 32)
}

func newHmacSHA512Key(key ipsecKey) (ipsecKey, error) {
	return newCbcAesKey(key, "hmac(sha512)", 64, 32)
}

func newCbcAesKey(key ipsecKey, algo string, authKeylen int, cipherKeyLen int) (ipsecKey, error) {
	authKey, err := generateRandomHex(authKeylen)
	if err != nil {
		return ipsecKey{}, err
	}
	cipherKey, err := generateRandomHex(cipherKeyLen)
	if err != nil {
		return ipsecKey{}, err
	}
	newKey := ipsecKey{
		spi:        key.nextSPI(),
		spiSuffix:  key.spiSuffix,
		algo:       algo,
		key:        authKey,
		cipherMode: "cbc(aes)",
		cipherKey:  cipherKey,
	}
	return newKey, nil
}
