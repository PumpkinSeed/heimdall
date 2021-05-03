package main

import (
	"os"

	"github.com/PumpkinSeed/heimdall/cmd/common"
	"github.com/PumpkinSeed/heimdall/cmd/flags"
	initcommand "github.com/PumpkinSeed/heimdall/cmd/init"
	"github.com/PumpkinSeed/heimdall/cmd/server"
	"github.com/PumpkinSeed/heimdall/cmd/token"
	"github.com/PumpkinSeed/heimdall/cmd/unseal"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var app = cli.App{
	Commands: []*cli.Command{
		server.Cmd,
		unseal.Cmd,
		initcommand.Cmd,
		token.Cmd,
	},
	Flags: []cli.Flag{
		flags.Verbose,
		flags.LogOutput,
		flags.LogAdditional,
	},
	Before: common.Before,
}

func main() {
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
