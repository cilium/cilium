package types

type PingResponse struct {
	NodeAddress string       `json:"node-address"`
	Opts        *BoolOptions `json:"options"`
}
