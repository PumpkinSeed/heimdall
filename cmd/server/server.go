package server

import (
	"github.com/PumpkinSeed/heimdall/cmd/server/flags"
	"github.com/PumpkinSeed/heimdall/internal/api/grpc"
	"github.com/PumpkinSeed/heimdall/internal/api/rest"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var Cmd = &cli.Command{
	Name:   "server",
	Before: checkFlags,
	Action: serve,
	Flags: []cli.Flag{
		flags.Grpc,
		flags.Rest,
	},
}

func checkFlags(ctx *cli.Context) error {
	if ctx.NumFlags() == 0 {
		log.Warn("Consider adding flags to turn on specific services, learn more about flags with --help")
	}

	return nil
}

func serve(ctx *cli.Context) error {
	errCh := make(chan error)
	services := run(ctx, errCh)
	for services > 0 {
		err := <-errCh
		if err != nil {
			return err
		}
		services--
	}

	return nil
}

func run(ctx *cli.Context, errCh chan error) int {
	var startedServices int
	if grpcAddress := ctx.String(flags.NameGrpc); grpcAddress != "" {
		grpc.Serve(errCh, grpcAddress)
		startedServices++
	}
	if restAddress := ctx.String(flags.NameRest); restAddress != "" {
		rest.Serve(errCh, restAddress)
		startedServices++
	}

	return startedServices
}
