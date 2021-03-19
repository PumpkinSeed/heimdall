package main

import (
	"os"

	"github.com/PumpkinSeed/heimdall/cmd/server"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var app = cli.App{
	Commands: []*cli.Command{
		server.Cmd,
	},
}

func main() {
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
