package main

import (
	"os"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	initcommand "github.com/PumpkinSeed/heimdall/cmd/init"
	"github.com/PumpkinSeed/heimdall/cmd/server"
	"github.com/PumpkinSeed/heimdall/cmd/unseal"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var app = cli.App{
	Commands: []*cli.Command{
		server.Cmd,
		unseal.Cmd,
		initcommand.Cmd,
	},
	Flags: []cli.Flag{
		flags.Verbose,
	},
	Before: func(ctx *cli.Context) error {
		if ctx.Bool(flags.NameVerbose) {
			log.SetLevel(log.DebugLevel)
		}
		return nil
	},
}

func main() {
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
