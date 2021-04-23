package storage

import (
	"github.com/PumpkinSeed/heimdall/cmd/flags"
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
		return inmem.NewInmem(nil, logger.Of(log.StandardLogger()))
	}
	return consul.NewConsulBackend(map[string]string{
		"address": ctx.String(flags.NameConsulAddress),
		"token":   ctx.String(flags.NameConsulToken),
	}, logger.Of(log.StandardLogger()))
}
