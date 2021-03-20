package server

import (
	"github.com/PumpkinSeed/heimdall/cmd/server/flags"
	"github.com/PumpkinSeed/heimdall/internal/api/grpc"
	"github.com/PumpkinSeed/heimdall/internal/api/rest"
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
	errCh := make(chan error, serviceCount)

	grpc.Serve(errCh, ctx.String(flags.NameGrpc))
	rest.Serve(errCh, ctx.String(flags.NameRest))

	for i := 0; i < serviceCount; i++ {
		err := <-errCh
		if err != nil {
			return err
		}
	}

	return nil
}
