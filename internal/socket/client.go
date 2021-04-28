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
	resp, err := Do(ctx, req)

	log.Infof("Client got: %s", string(resp))
	return err
}

func Do(ctx *cli.Context, req structs.SocketRequest) ([]byte, error) {
	c, err := net.Dial("unix", ctx.String(flags.NameSocket))
	if err != nil {
		return nil, err
	}
	defer c.Close()

	log.Debugf("initializing Bifröst (Heimdall's init operator")

	if _, err := c.Write(req.MustMarshal()); err != nil {
		return nil, err
	}
	return readResult(c)
}

func readResult(r io.Reader) ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[0:n], nil
}
