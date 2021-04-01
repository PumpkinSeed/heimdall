package server

import (
	"github.com/PumpkinSeed/heimdall/cmd/server/flags"
	"github.com/PumpkinSeed/heimdall/internal/api/grpc"
	"github.com/PumpkinSeed/heimdall/internal/api/rest"
	"github.com/PumpkinSeed/heimdall/internal/api/socket"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/storage"
	"github.com/hashicorp/vault/sdk/physical"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var Cmd = &cli.Command{
	Name:   "server",
	Action: serve,
	Before: setup,
	Flags: []cli.Flag{
		flags.Grpc,
		flags.Rest,
		flags.Socket,
		flags.Threshold,
		flags.ConsulAddress,
		flags.ConsulToken,
	},
}

func serve(ctx *cli.Context) error {
	finished := make(chan struct{}, 1)

	b := createBackendConnection(ctx)

	serverExecutor(grpc.Serve, ctx.String(flags.NameGrpc), b, finished)
	serverExecutor(rest.Serve, ctx.String(flags.NameRest), b, finished)
	serverExecutor(socket.Serve, ctx.String(flags.NameSocket), b, finished)

	<-finished

	return nil
}

func createBackendConnection(ctx *cli.Context) physical.Backend {
	b, err := storage.Create(ctx)
	if err != nil {
		log.Fatal(err)
	}

	return b
}

func serverExecutor(fn func(string, physical.Backend) error, str string, b physical.Backend, finisher chan struct{}) {
	go func() {
		if err := fn(str, b); err != nil {
			log.Error(err)
		}
		finisher <- struct{}{}
	}()
}

func setup(ctx *cli.Context) error {
	unseal.Get().Init(ctx.Int(flags.NameThreshold))

	return nil
}
