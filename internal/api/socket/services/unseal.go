package services

import (
	"context"

	"github.com/PumpkinSeed/heimdall/internal/structs"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	log "github.com/sirupsen/logrus"
)

type Unseal struct {
	state *unseal.Unseal
}

func NewUnseal(u *unseal.Unseal) Unseal {
	return Unseal{state: u}
}

func (u Unseal) Handler(ctx context.Context, req structs.SocketRequest) (structs.SocketResponse, error) {
	if status := u.state.Status(); status.Unsealed {
		return structs.SocketResponse{
			Data: []byte(status.String()),
		}, nil
	}
	done, err := u.state.Unseal(ctx, string(req.Data))
	if err != nil {
		return structs.SocketResponse{
			Data: []byte(u.state.Status().String()),
		}, err
	}
	if !done {
		log.Debug("Unseal not done yet")

		return structs.SocketResponse{
			Data: []byte(u.state.Status().String()),
		}, nil
	}
	if err := u.state.Keyring(ctx); err != nil {
		log.Debug("Keyring init error")

		return structs.SocketResponse{
			Data: []byte(u.state.Status().String()),
		}, err
	}
	barrierPath, err := u.state.Mount(ctx)
	if err != nil {
		log.Debug("Mount error")

		return structs.SocketResponse{
			Data: []byte(u.state.Status().String()),
		}, err
	}
	if err := u.state.PostProcess(ctx, barrierPath); err != nil {
		log.Debug("Post process error")

		return structs.SocketResponse{
			Data: []byte(u.state.Status().String()),
		}, err
	}
	utils.Memzero(req.Data)

	return structs.SocketResponse{
		Data: []byte(u.state.Status().String()),
	}, nil
}
