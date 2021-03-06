package services

import (
	"context"
	"encoding/json"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	initcommand "github.com/PumpkinSeed/heimdall/pkg/init"
)

type Init struct {
	unseal *unseal.Unseal
}

func NewInit(u *unseal.Unseal) Init {
	return Init{
		unseal: u,
	}
}

func (i Init) Handler(ctx context.Context, req structs.SocketRequest) (structs.SocketResponse, error) {
	initParams := initcommand.Request{}
	if err := json.Unmarshal(req.Data, &initParams); err != nil {
		return structs.SocketResponse{}, errors.Wrap(err, "socket unmarshal error", errors.CodeApiSocketInitUnmarshal)
	}

	init := initcommand.NewInit(i.unseal)

	i.unseal.TotalShares = initParams.SecretShares
	i.unseal.Threshold = initParams.SecretThreshold

	res, err := init.Initialize(ctx, initParams)
	if err != nil {
		return structs.SocketResponse{}, errors.Wrap(err, "socket init error", errors.CodeApiSocketInit)
	}

	data, err := json.Marshal(res)
	if err != nil {
		return structs.SocketResponse{}, errors.Wrap(err, "socket init error", errors.CodeApiSocketInitMarshal)
	}

	return structs.SocketResponse{
		Data: data,
	}, nil
}
