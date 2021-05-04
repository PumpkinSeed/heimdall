package server

import (
	"context"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/internal/api/grpc"
	"github.com/PumpkinSeed/heimdall/internal/api/http"
	"github.com/PumpkinSeed/heimdall/internal/api/socket"
	"github.com/PumpkinSeed/heimdall/internal/errors"
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
		flags.HTTP,
		flags.Socket,
		flags.Threshold,
		flags.ConsulAddress,
		flags.ConsulToken,
		flags.InMemory,
		flags.DefaultEnginePath,
		flags.DisableGrpc,
		flags.DisableHttp,
	},
}

func serve(ctx *cli.Context) error {
	finished := make(chan struct{}, 1)

	if err := setupEnvironment(ctx); err != nil {
		return errors.Wrap(err, "", errors.CodeCmdServer)
	}

	if !ctx.Bool(flags.NameDisableGrpc) {
		serverExecutor(grpc.Serve, ctx.String(flags.NameGrpc), finished)
	}
	if !ctx.Bool(flags.NameDisableHttp) {
		serverExecutor(http.Serve, ctx.String(flags.NameHttp), finished)
	}
	serverExecutor(socket.Serve, ctx.String(flags.NameSocket), finished)

	<-finished

	return nil
}

func setupEnvironment(ctx *cli.Context) error {
	b, err := createBackendConnection(ctx)
	if err != nil {
		return errors.Wrap(err, "environment setup error", errors.CodeCmdServerEnvSetup)
	}
	sb, err := createLogicalStorage(b)
	if err != nil {
		return errors.Wrap(err, "environment setup error", errors.CodeCmdServerEnvSetup)
	}
	u := unseal.Get()
	u.SetBackend(b)
	u.SetSecurityBarrier(sb)
	u.SetDefaultEnginePath(ctx.String(flags.NameDefaultEnginePath))
	if ctx.Bool(flags.NameInMemory) {
		err := u.DevMode(context.Background())
		if err != nil {
			return errors.Wrap(err, "environment setup dev mode error", errors.CodeCmdServerEnvSetup)
		}
		return nil
	}

	return nil
}

func createLogicalStorage(b physical.Backend) (vault.SecurityBarrier, error) {
	l, err := vault.NewAESGCMBarrier(b)
	if err != nil {
		return nil, errors.Wrap(err, "logical backend setup error", errors.CodeCmdServerEnvSetupLogical)
	}

	return l, nil
}

func createBackendConnection(ctx *cli.Context) (physical.Backend, error) {
	b, err := storage.Create(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "physical backend setup error", errors.CodeCmdServerEnvSetupPhysical)
	}

	return b, nil
}

func serverExecutor(fn func(string) error, str string, finisher chan struct{}) {
	go func() {
		if err := fn(str); err != nil {
			log.Error(errors.Wrap(err, "server execution error", errors.CodeCmdServerExecute))
		}
		finisher <- struct{}{}
	}()
}

func setup(ctx *cli.Context) error {
	unseal.Get().Init(ctx.Int(flags.NameThreshold))

	return nil
}
