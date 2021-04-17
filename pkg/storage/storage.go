package storage

import (
	"github.com/PumpkinSeed/heimdall/cmd/server/flags"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/physical/consul"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/urfave/cli/v2"
)

// TODO refactor it to be able to handle multiple storages
func Create(ctx *cli.Context) (physical.Backend, error) {
	return consul.NewConsulBackend(map[string]string{
		"address": ctx.String(flags.NameConsulAddress),
		"token":   ctx.String(flags.NameConsulToken),
	}, logging.NewVaultLogger(log.Debug))
}
