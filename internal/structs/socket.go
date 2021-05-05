package structs

import (
	"encoding/json"
	"errors"
)

const (
	SocketUnknown = iota
	SocketUnseal
	SocketInit
	TokenCreate
)

type SocketType int

var (
	ErrUnknownRequest = errors.New("unknown request type")
)

type SocketRequest struct {
	Type SocketType `json:"type"`
	Data []byte     `json:"data"`
}

func (sr SocketRequest) MustMarshal() []byte {
	res, err := json.Marshal(sr)
	if err != nil {
		panic(err)
	}

	return res
}

type SocketResponse struct {
	Data []byte `json:"data"`
}
