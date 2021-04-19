package server

import (
	"context"
	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/internal/api/grpc"
	"github.com/PumpkinSeed/heimdall/internal/api/rest"
	"github.com/PumpkinSeed/heimdall/internal/api/socket"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/storage"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault"
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
		flags.InMem,
	},
}

func serve(ctx *cli.Context) error {
	finished := make(chan struct{}, 1)

	if err := setupEnvironment(ctx); err != nil {
		return err
	}

	serverExecutor(grpc.Serve, ctx.String(flags.NameGrpc), finished)
	serverExecutor(rest.Serve, ctx.String(flags.NameRest), finished)
	serverExecutor(socket.Serve, ctx.String(flags.NameSocket), finished)

	<-finished

	return nil
}

func setupEnvironment(ctx *cli.Context) error {
	b, err := createBackendConnection(ctx)
	if err != nil {
		return err
	}
	sb, err := createLogicalStorage(b)
	if err != nil {
		return err
	}
	u := unseal.Get()
	u.SetBackend(b)
	u.SetSecurityBarrier(sb)
	if ctx.Bool(flags.NameInMemory) {
		u.DevMode(context.Background())
	}
	return nil
}

func createLogicalStorage(b physical.Backend) (vault.SecurityBarrier, error) {
	l, err := vault.NewAESGCMBarrier(b)
	if err != nil {
		return nil, err
	}

	return l, nil
}

func createBackendConnection(ctx *cli.Context) (physical.Backend, error) {
	b, err := storage.Create(ctx)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func serverExecutor(fn func(string) error, str string, finisher chan struct{}) {
	go func() {
		if err := fn(str); err != nil {
			log.Error(err)
		}
		finisher <- struct{}{}
	}()
}

func setup(ctx *cli.Context) error {
	unseal.Get().Init(ctx.Int(flags.NameThreshold))

	return nil
}
