package token

import (
	"encoding/json"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/internal/socket"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	"github.com/PumpkinSeed/heimdall/pkg/token"
	"github.com/urfave/cli/v2"
)

var Cmd = &cli.Command{
	Name:   "token",
	Action: action,
	Flags: []cli.Flag{
		flags.Socket,
		flags.TokenId,
	},
}

func action(ctx *cli.Context) error {
	req := token.Request{
		ID: ctx.String(flags.NameTokenID),
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return socket.Action(ctx, structs.SocketRequest{
		Type: structs.TokenCreate,
		Data: data,
	})
}
