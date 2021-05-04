package storage

import (
	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/internal/logger"
	"github.com/hashicorp/vault/physical/consul"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/sdk/physical/inmem"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// TODO refactor it to be able to handle multiple storages
func Create(ctx *cli.Context) (physical.Backend, error) {
	if ctx.Bool(flags.NameInMemory) {
		log.Info("starting the server with in memory storage")
		newInmem, err := inmem.NewInmem(nil, logger.Of(log.StandardLogger()))
		if err != nil {
			return nil, errors.Wrap(err, "create storage in-memory config error", errors.CodePkgStorageInMemory)
		}
		return newInmem, nil
	}
	backend, err := consul.NewConsulBackend(map[string]string{
		"address": ctx.String(flags.NameBackendAddress),
		"token":   ctx.String(flags.NameBackendCredentials),
	}, logger.Of(log.StandardLogger()))
	if err != nil {
		return nil, errors.Wrap(err, "create storage consul config error", errors.CodePkgStorageConsul)
	}
	return backend, nil
}
