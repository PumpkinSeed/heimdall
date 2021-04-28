package tests

import (
	"flag"
	"github.com/PumpkinSeed/heimdall/cmd/flags"
	initcommand "github.com/PumpkinSeed/heimdall/cmd/init"
	"github.com/PumpkinSeed/heimdall/cmd/server"
	"github.com/urfave/cli/v2"
	"log"
	"testing"
	"time"
)

func TestEncrypt(t *testing.T) {
	set := flag.NewFlagSet("server", 0)
	set.String(flags.NameConsulToken, "89C2B840-CDE0-4E77-ACAF-73EABB7A489B", "doc")
	set.String(flags.NameConsulAddress, "127.0.0.1:8500", "doc")
	set.String(flags.NameGrpc, "0.0.0.0:9090", "doc")
	set.String(flags.NameRest, "0.0.0.0:10080", "doc")
	set.String(flags.NameSocket, "/tmp/mellek.sock", "doc")
	set.Int(flags.NameThreshold, 3, "doc")
	set.Int(flags.NameTotalShares, 5, "doc")
	ctx := cli.NewContext(nil, set, nil)

	var done chan struct{}
	go func (chan struct{}) {
		if err := server.Cmd.Action(ctx); err != nil {
			log.Print(err)
		}
		done <- struct{}{}
	} (done)

	time.Sleep(10*time.Second)

	if err := initcommand.Cmd.Action(ctx); err != nil {
		log.Print(err)
	}

	<- done
}
