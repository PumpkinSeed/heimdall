package services

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/PumpkinSeed/heimdall/internal/structs"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/token"
)

const msgInvalidRootTokenID = "invalid root token id"

type TokenCreate struct {
	state      *unseal.Unseal
	tokenStore *token.TokenStore
}

func NewTokenCreate(u *unseal.Unseal) TokenCreate {
	return TokenCreate{
		state:      u,
		tokenStore: token.NewTokenStore(u),
	}
}

func (t TokenCreate) Handler(ctx context.Context, req structs.SocketRequest) (structs.SocketResponse, error) {
	if status := t.state.Status(); !status.Unsealed {
		return structs.SocketResponse{}, errors.New("Heimdall sealed")
	}
	var token token.Request
	if err := json.Unmarshal(req.Data, &token); err != nil {
		return structs.SocketResponse{}, err
	}
	if rootTokenValid, err := t.tokenStore.CheckToken(ctx, token.RootTokenID); err != nil {
		return structs.SocketResponse{}, err
	} else if !rootTokenValid {
		return structs.SocketResponse{
			Data: []byte(msgInvalidRootTokenID),
		}, nil
	}
	rootToken, err := t.tokenStore.GenRootToken(ctx, token.ID)
	data, err := json.Marshal(rootToken)
	if err != nil {
		return structs.SocketResponse{}, err
	}
	return structs.SocketResponse{
		Data: data,
	}, err
}