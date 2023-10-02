package types

type IPSec interface {
	AuthKeySize() int
	SPI() uint8
}
