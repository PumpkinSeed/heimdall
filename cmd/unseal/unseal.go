package unseal

import (
	"io"
	"net"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var Cmd = &cli.Command{
	Name:   "unseal",
	Action: action,
	Flags: []cli.Flag{
		flags.Socket,
	},
}

func action(ctx *cli.Context) error {
	c, err := net.Dial("unix", ctx.String(flags.NameSocket))
	if err != nil {
		return err
	}
	defer c.Close()

	key := ctx.Args().First()
	log.Debugf("sending key: %s", key)

	if _, err := c.Write([]byte(key)); err != nil {
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
