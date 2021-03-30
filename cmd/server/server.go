package server

import (
	"github.com/PumpkinSeed/heimdall/cmd/server/flags"
	"github.com/PumpkinSeed/heimdall/internal/api/grpc"
	"github.com/PumpkinSeed/heimdall/internal/api/rest"
	"github.com/PumpkinSeed/heimdall/internal/api/socket"
	"github.com/hashicorp/vault/physical/consul"
	"github.com/hashicorp/vault/sdk/physical"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var Cmd = &cli.Command{
	Name:   "server",
	Action: serve,
	Flags: []cli.Flag{
		flags.Grpc,
		flags.Rest,
		flags.Socket,
	},
}

func serve(ctx *cli.Context) error {
	finished := make(chan struct{}, 1)

	b, err := consul.NewConsulBackend(map[string]string{
		"address": "http://localhost:8500",
		"token":   "89C2B840-CDE0-4E77-ACAF-73EABB7A489B",
	}, nil)
	if err != nil {
		return err
	}

	serverExecutor(grpc.Serve, ctx.String(flags.NameGrpc), b, finished)
	serverExecutor(rest.Serve, ctx.String(flags.NameRest), b, finished)
	serverExecutor(socket.Serve, ctx.String(flags.NameSocket), b, finished)

	<-finished

	return nil
}

func serverExecutor(fn func(string, physical.Backend) error, str string, b physical.Backend, finisher chan struct{}) {
	go func() {
		if err := fn(str, b); err != nil {
			log.Error(err)
		}
		finisher <- struct{}{}
	}()
}
