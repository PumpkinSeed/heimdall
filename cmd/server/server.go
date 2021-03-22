package server

import (
	"github.com/PumpkinSeed/heimdall/cmd/server/flags"
	"github.com/PumpkinSeed/heimdall/internal/api/grpc"
	"github.com/PumpkinSeed/heimdall/internal/api/rest"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const serviceCount = 2

var Cmd = &cli.Command{
	Name:   "server",
	Action: serve,
	Flags: []cli.Flag{
		flags.Grpc,
		flags.Rest,
	},
}

func serve(ctx *cli.Context) error {
	finished := make(chan struct{}, 1)

	serverExecutor(grpc.Serve, ctx.String(flags.NameGrpc), finished)
	serverExecutor(rest.Serve, ctx.String(flags.NameRest), finished)

	<- finished

	return nil
}

func serverExecutor(fn func(string) error, str string, finisher chan struct{}) {
	go func() {
		if err := fn(str); err != nil {
			log.Error(err)
		}
		finisher <- struct{}{}
	} ()
}
