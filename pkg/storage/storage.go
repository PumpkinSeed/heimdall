package storage

import (
	"github.com/PumpkinSeed/heimdall/cmd/flags"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/physical/consul"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/sdk/physical/inmem"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// TODO refactor it to be able to handle multiple storages
func Create(ctx *cli.Context) (physical.Backend, error) {
	if ctx.Bool(flags.NameInMemory) {
		logrus.Info("starting the server with in memory storage")
		return inmem.NewInmem(nil, logging.NewVaultLogger(log.Debug))
	}
	return consul.NewConsulBackend(map[string]string{
		"address": ctx.String(flags.NameConsulAddress),
		"token":   ctx.String(flags.NameConsulToken),
	}, logging.NewVaultLogger(log.Debug))
}
