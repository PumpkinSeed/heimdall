package init

import (
	"encoding/json"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/internal/socket"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	initcommand "github.com/PumpkinSeed/heimdall/pkg/init"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var Cmd = &cli.Command{
	Name:    "init",
	Aliases: []string{"prepare", "prepare-for-battle"},
	Action:  initAction,
	Flags: []cli.Flag{
		flags.Socket,
		flags.Threshold,
		flags.TotalShares,
	},
}

func initAction(ctx *cli.Context) error {
	log.Debugf("initializing Bifröst (Heimdall's init operator")

	initParams := initcommand.Request{
		SecretShares:    ctx.Int(flags.NameTotalShares),
		SecretThreshold: ctx.Int(flags.NameThreshold),
	}

	data, err := json.Marshal(initParams)
	if err != nil {
		return errors.Wrap(err, "init bind error", errors.CodeCmdInit)
	}

	if err := socket.Action(ctx, structs.SocketRequest{
		Type: structs.SocketInit,
		Data: data,
	}); err != nil {
		return errors.Wrap(err, "init action error", errors.CodeCmdInit)
	}
	return nil
}
