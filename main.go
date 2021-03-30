package main

import (
	"os"

	"github.com/PumpkinSeed/heimdall/cmd/server"
	"github.com/PumpkinSeed/heimdall/cmd/unseal"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const verbose = "verbose"

var app = cli.App{
	Commands: []*cli.Command{
		server.Cmd,
		unseal.Cmd,
	},
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name: verbose,
		},
	},
	Before: func(ctx *cli.Context) error {
		if ctx.Bool(verbose) {
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
