package services

import (
	"context"
	"encoding/json"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	initcommand "github.com/PumpkinSeed/heimdall/pkg/init"
	"github.com/hashicorp/vault/vault"
)

type Init struct {

}

func NewInit() Init {
	return Init{}
}

func (i Init) Handler(ctx context.Context, req structs.SocketRequest) (structs.SocketResponse, error) {
	initParams := initcommand.Request{}
	if err := json.Unmarshal(req.Data,&initParams); err != nil {
		return structs.SocketResponse{}, err
	}

	u := unseal.Get()
	init := initcommand.NewInit(u)
	table := &vault.MountTable{
		Type:    "mounts",
		Entries: []*vault.MountEntry{},
	}

	init.SetMountTables(table)

	res, err := init.Initialize(initParams)
	if err != nil {
		return structs.SocketResponse{}, err
	}

	data, err := json.Marshal(res)
	if err != nil {
		return structs.SocketResponse{}, err
	}

	return structs.SocketResponse{
		Data: data,
	}, nil

}
