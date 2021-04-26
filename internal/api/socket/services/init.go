package services

import (
	"context"
	"encoding/json"

	"github.com/PumpkinSeed/heimdall/internal/structs"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	initcommand "github.com/PumpkinSeed/heimdall/pkg/init"
)

type Init struct{}

func NewInit() Init {
	return Init{}
}

func (i Init) Handler(ctx context.Context, req structs.SocketRequest) (structs.SocketResponse, error) {
	initParams := initcommand.Request{}
	if err := json.Unmarshal(req.Data, &initParams); err != nil {
		return structs.SocketResponse{}, err
	}

	u := unseal.Get()
	init := initcommand.NewInit(u)

	// set totalShares and threshold if it's not empty
	if initParams.SecretShares != 0 {
		u.TotalShares = initParams.SecretShares
	}
	if initParams.SecretThreshold != 0 {
		u.Threshold = initParams.SecretThreshold
	}

	res, err := init.Initialize(ctx, initParams)
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
