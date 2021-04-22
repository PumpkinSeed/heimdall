package init

import (
	"encoding/json"
	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	initcommand "github.com/PumpkinSeed/heimdall/pkg/init"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"io"
	"net"
)

var Cmd = &cli.Command{
	Name:   "init",
	Action: initAction,
	Flags: []cli.Flag{
		flags.Socket,
	},
}

func initAction(ctx *cli.Context) error {
	c, err := net.Dial("unix", ctx.String(flags.NameSocket))
	if err != nil {
		return err
	}
	defer c.Close()

	log.Debugf("initializing Bifröst (Heimdall's init operator")
	initParams := initcommand.Request{
		SecretShares:    5,
		SecretThreshold: 3,
	}
	data, err := json.Marshal(initParams)
	if err != nil {
		return err
	}

	if _, err := c.Write(structs.SocketRequest{
		Type: structs.SocketInit,
		Data: data,
	}.MustMarshal()); err != nil {
		return err
	}
	return readResult(c)
}

func readResult(r io.Reader) error {
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil {
		return err
	}
	log.Infof("Client got: %s", string(buf[0:n]))

	return nil
}
