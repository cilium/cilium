// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"context"
	"crypto/rand"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium-cli/defaults"
)

type ipsecKey struct {
	spi        int
	spiSuffix  bool
	algo       string // Purposefully ambiguous here because of modes like GCM
	key        string
	size       int
	cipherMode string
	cipherKey  string
}

// IPsecRotateKey rotates IPsec key.
func (s *Status) IPsecRotateKey(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	secret, err := s.client.GetSecret(ctx, s.params.CiliumNamespace, defaults.EncryptionSecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to fetch IPsec secret: %s", err)
	}

	key, err := ipsecKeyFromString(string(secret.Data["keys"]))
	if err != nil {
		return err
	}

	newKey, err := key.rotate()
	if err != nil {
		return fmt.Errorf("failed to rotate IPsec key: %s", err)
	}

	patch := []byte(`{"stringData":{"keys":"` + newKey.String() + `"}}`)
	_, err = s.client.PatchSecret(ctx, s.params.CiliumNamespace, defaults.EncryptionSecretName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to patch IPsec secret with new key: %s", err)
	}

	_, err = fmt.Printf("IPsec key successfully rotated, new key SPI: %d\n", newKey.spi)
	return err
}

func (k ipsecKey) String() string {
	spiSuffix := ""
	if k.spiSuffix {
		spiSuffix = "+"
	}
	if k.cipherMode == "" {
		return fmt.Sprintf("%d%s %s %s %d", k.spi, spiSuffix, k.algo, k.key, k.size)
	}
	return fmt.Sprintf("%d%s %s %s %s %s", k.spi, spiSuffix, k.algo, k.key, k.cipherMode, k.cipherKey)
}

var (
	ipsecKeyRegex       = regexp.MustCompile(`^([[:digit:]]+\+?)[[:space:]](\S+)[[:space:]]([[:alnum:]]+)[[:space:]]([[:digit:]]+)$`)
	cipherIPsecKeyRegex = regexp.MustCompile(`^([[:digit:]]+\+?)[[:space:]](\S+)[[:space:]]([[:alnum:]]+)[[:space:]](\S+)[[:space:]]([[:alnum:]]+)$`)
	ipsecParsers        = map[*regexp.Regexp]func([]string) (ipsecKey, error){
		ipsecKeyRegex:       keyFromSlice,
		cipherIPsecKeyRegex: cipherKeyFromSlice,
	}
)

func ipsecKeyFromString(s string) (ipsecKey, error) {
	for matcher, parser := range ipsecParsers {
		if matcher.MatchString(s) {
			return parser(matcher.FindStringSubmatch(s))
		}
	}
	return ipsecKey{}, fmt.Errorf("IPsec key has unsupported format")
}

func keyFromSlice(parts []string) (ipsecKey, error) {
	if len(parts) != 5 {
		return ipsecKey{}, fmt.Errorf("IPsec key invalid [expected parts: 5, actual parts: %d]", len(parts))
	}
	spiSuffix := false
	if strings.HasSuffix(parts[1], "+") {
		spiSuffix = true
		parts[1] = strings.TrimSuffix(parts[1], "+")
	}
	spi, err := strconv.Atoi(parts[1])
	if err != nil {
		return ipsecKey{}, fmt.Errorf("invalid IPsec key SPI: %s", parts[1])
	}
	size, err := strconv.Atoi(parts[4])
	if err != nil {
		return ipsecKey{}, fmt.Errorf("invalid IPsec key size: %s", parts[4])
	}
	key := ipsecKey{
		spi:       spi,
		spiSuffix: spiSuffix,
		algo:      parts[2],
		key:       parts[3],
		size:      size,
	}
	return key, nil
}

func cipherKeyFromSlice(parts []string) (ipsecKey, error) {
	if len(parts) != 6 {
		return ipsecKey{}, fmt.Errorf("IPsec key invalid [expected parts: 6, actual parts: %d]", len(parts))
	}
	spiSuffix := false
	if strings.HasSuffix(parts[1], "+") {
		spiSuffix = true
		parts[1] = strings.TrimSuffix(parts[1], "+")
	}
	spi, err := strconv.Atoi(parts[1])
	if err != nil {
		return ipsecKey{}, fmt.Errorf("invalid cipher IPsec key SPI: %s", parts[1])
	}
	key := ipsecKey{
		spi:        spi,
		spiSuffix:  spiSuffix,
		algo:       parts[2],
		key:        parts[3],
		cipherMode: parts[4],
		cipherKey:  parts[5],
	}
	return key, nil
}

const maxIPsecSPI = 16

func (k ipsecKey) rotate() (ipsecKey, error) {
	key, err := generateRandomHex(len(k.key))
	if err != nil {
		return ipsecKey{}, fmt.Errorf("failed to generate authentication key: %s", err)
	}

	cipherKey := ""
	if k.cipherMode != "" {
		cipherKey, err = generateRandomHex(len(k.cipherKey))
		if err != nil {
			return ipsecKey{}, fmt.Errorf("failed to generate symmetric encryption key: %s", err)
		}
	}

	spi := k.spi + 1
	if spi >= maxIPsecSPI {
		spi = 1
	}
	newKey := ipsecKey{
		spi:        spi,
		spiSuffix:  k.spiSuffix,
		algo:       k.algo,
		key:        key,
		size:       k.size,
		cipherMode: k.cipherMode,
		cipherKey:  cipherKey,
	}
	return newKey, nil
}

func generateRandomHex(size int) (string, error) {
	buf := make([]byte, size/2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	random := strings.Builder{}
	random.Grow(len(buf))
	for _, c := range buf {
		random.WriteString(fmt.Sprintf("%02x", c))
	}
	return random.String(), nil
}
