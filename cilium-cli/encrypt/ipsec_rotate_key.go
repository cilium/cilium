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
	spi       int
	spiSuffix bool
	algo      string
	random    string
	size      int
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
	return fmt.Sprintf("%d%s %s %s %d", k.spi, spiSuffix, k.algo, k.random, k.size)
}

var ipsecKeyRegex = regexp.MustCompile(`^([[:digit:]]+\+?)[[:space:]](\S+)[[:space:]]([[:alnum:]]+)[[:space:]]([[:digit:]]+)$`)

func ipsecKeyFromString(s string) (ipsecKey, error) {
	parts := ipsecKeyRegex.FindStringSubmatch(s)
	if len(parts) != 5 {
		return ipsecKey{}, fmt.Errorf("IPsec key has unsupported format")
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
		random:    parts[3],
		size:      size,
	}
	return key, nil
}

const maxIPsecSPI = 16

func (k ipsecKey) rotate() (ipsecKey, error) {
	buf := make([]byte, len(k.random)/2)
	if _, err := rand.Read(buf); err != nil {
		return ipsecKey{}, fmt.Errorf("failed to generate random part: %s", err)
	}
	random := &strings.Builder{}
	random.Grow(len(buf))
	for _, c := range buf {
		random.WriteString(fmt.Sprintf("%02x", c))
	}

	spi := k.spi + 1
	if spi >= maxIPsecSPI {
		spi = 1
	}
	key := ipsecKey{
		spi:       spi,
		spiSuffix: k.spiSuffix,
		algo:      k.algo,
		random:    random.String(),
		size:      k.size,
	}
	return key, nil
}
