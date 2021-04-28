package socket

import (
	"io"
	"net"

	"github.com/PumpkinSeed/heimdall/cmd/flags"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func Action(ctx *cli.Context, req structs.SocketRequest) error {
	c, err := net.Dial("unix", ctx.String(flags.NameSocket))
	if err != nil {
		return err
	}
	defer c.Close()

	log.Debugf("initializing Bifröst (Heimdall's init operator")

	if _, err := c.Write(req.MustMarshal()); err != nil {
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
