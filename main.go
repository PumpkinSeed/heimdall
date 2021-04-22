package main

import (
	"os"

	"github.com/PumpkinSeed/heimdall/cmd/common"
	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/cmd/server"
	"github.com/PumpkinSeed/heimdall/cmd/unseal"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var app = cli.App{
	Commands: []*cli.Command{
		server.Cmd,
		unseal.Cmd,
	},
	Flags: []cli.Flag{
		flags.Verbose,
		flags.LogOutput,
		flags.LogOutputNetwork,
		flags.LogOutputAddress,
	},
	Before: common.Before,
}

func main() {
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
