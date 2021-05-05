package unseal

import (
	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/internal/socket"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var Cmd = &cli.Command{
	Name:    "unseal",
	Aliases: []string{"open-the-bifrost"},
	Action:  action,
	Flags: []cli.Flag{
		flags.Socket,
	},
}

func action(ctx *cli.Context) error {
	key := ctx.Args().First()
	log.Debugf("sending key: %s", key)

	return socket.Action(ctx, structs.SocketRequest{
		Type: structs.SocketUnseal,
		Data: []byte(key),
	})
}
